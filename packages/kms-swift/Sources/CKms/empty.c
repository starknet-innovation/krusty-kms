// C helpers used by the Swift binding that are not part of libkms itself.
#include <stddef.h>
#include <string.h>

#if defined(__linux__)
#include <strings.h>
#endif

/// Best-effort wipe that resists dead-store elimination (unlike memset).
void kms_secure_wipe(void *ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }
#if defined(__APPLE__)
    // C11 Annex K — available via Darwin and not elided like memset.
    (void)memset_s(ptr, len, 0, len);
#elif defined(__linux__)
    explicit_bzero(ptr, len);
#else
    {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (len--) {
            *p++ = 0;
        }
    }
#endif
}
