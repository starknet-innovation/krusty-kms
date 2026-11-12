#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#elif defined(__linux__)
#include <sys/uio.h>
#include <unistd.h>
#else
#error "memory inspection supports macOS and Linux only"
#endif

/* No prologue: with -O2 -fomit-frame-pointer this leaf reads its caller's
 * stack boundary. x86 CALL has pushed one return address; ARM BL has not. */
__attribute__((noinline)) uintptr_t inspection_stack_boundary(void) {
    uintptr_t value;
#if defined(__aarch64__)
    __asm__ volatile("mov %0, sp" : "=r"(value));
#elif defined(__x86_64__)
    __asm__ volatile("mov %%rsp, %0" : "=r"(value));
    value += sizeof(uintptr_t);
#else
#error "memory inspection supports aarch64 and x86_64 only"
#endif
    return value;
}

typedef uintptr_t (*exercise_fn)(void *);
struct worker {
    exercise_fn exercise;
    void *fixture;
    _Atomic uintptr_t boundary;
    atomic_int release;
    uintptr_t low;
    uintptr_t high;
};

static void *run_worker(void *argument) {
    struct worker *worker = argument;
#if defined(__APPLE__)
    worker->high = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    worker->low = worker->high - pthread_get_stacksize_np(pthread_self());
#else
    pthread_attr_t attributes;
    void *base = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &attributes) ||
        pthread_attr_getstack(&attributes, &base, &size)) abort();
    pthread_attr_destroy(&attributes);
    worker->low = (uintptr_t)base;
    worker->high = worker->low + size;
#endif
    uintptr_t boundary = worker->exercise(worker->fixture);
    atomic_store_explicit(&worker->boundary, boundary, memory_order_release);
    /* No function calls or writes to the inspected stack after exercise. */
    while (!atomic_load_explicit(&worker->release, memory_order_acquire)) {
        atomic_signal_fence(memory_order_seq_cst);
    }
    return NULL;
}

/* Read through the OS into initialized memory on ANOTHER thread. No C or Rust
 * lvalue ever reads the target's uninitialized/dead stack bytes. */
int inspection_snapshot(exercise_fn exercise, void *fixture, unsigned char *out,
                        size_t length) {
    struct worker worker = { .exercise = exercise, .fixture = fixture,
        .boundary = ATOMIC_VAR_INIT(0), .release = ATOMIC_VAR_INIT(0) };
    pthread_attr_t attributes;
    pthread_t thread;
    if (pthread_attr_init(&attributes)) return 1;
    if (pthread_attr_setstacksize(&attributes, 2 * 1024 * 1024)) return 2;
    if (pthread_create(&thread, &attributes, run_worker, &worker)) return 3;
    pthread_attr_destroy(&attributes);
    uintptr_t boundary;
    while (!(boundary = atomic_load_explicit(&worker.boundary, memory_order_acquire))) {
        atomic_signal_fence(memory_order_seq_cst);
    }
    int error = 0;
    if (boundary > worker.high || boundary < worker.low + length) error = 6;
#if defined(__APPLE__)
    mach_vm_size_t copied = 0;
    kern_return_t result = error ? KERN_FAILURE : mach_vm_read_overwrite(mach_task_self(), boundary - length,
        length, (mach_vm_address_t)out, &copied);
    if (result != KERN_SUCCESS || copied != length) error = 4;
#else
    struct iovec local = { .iov_base = out, .iov_len = length };
    struct iovec remote = { .iov_base = (void *)(boundary - length), .iov_len = length };
    if (!error && process_vm_readv(getpid(), &local, 1, &remote, 1, 0) != (ssize_t)length) error = 4;
#endif
    atomic_store_explicit(&worker.release, 1, memory_order_release);
    if (pthread_join(thread, NULL)) return 5;
    return error;
}
