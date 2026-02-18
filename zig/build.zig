const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const native_fastpath = b.option(bool, "native_fastpath", "Build host-optimized native artifacts") orelse false;
    const parallel_provers = b.option(bool, "parallel_provers", "Enable opt-in proof parallelism features") orelse false;
    const precompute_budget_mb = b.option(u32, "precompute_budget_mb", "Precompute table memory budget in MB") orelse 16;

    const build_options = b.addOptions();
    build_options.addOption(bool, "native_fastpath", native_fastpath);
    build_options.addOption(bool, "parallel_provers", parallel_provers);
    build_options.addOption(u32, "precompute_budget_mb", precompute_budget_mb);

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.addOptions("build_options", build_options);

    const static_lib = b.addLibrary(.{
        .name = "kms",
        .root_module = root_mod,
        .linkage = .static,
    });

    const shared_lib = b.addLibrary(.{
        .name = "kms",
        .root_module = root_mod,
        .linkage = .dynamic,
    });

    b.installArtifact(static_lib);
    b.installArtifact(shared_lib);
    _ = b.addInstallHeaderFile(b.path("include/kms.h"), "kms.h");

    if (native_fastpath) {
        const native_target = b.resolveTargetQuery(.{});
        const native_mod = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = native_target,
            .optimize = optimize,
        });
        native_mod.addOptions("build_options", build_options);

        const native_static_lib = b.addLibrary(.{
            .name = "kms_native",
            .root_module = native_mod,
            .linkage = .static,
        });
        const native_shared_lib = b.addLibrary(.{
            .name = "kms_native",
            .root_module = native_mod,
            .linkage = .dynamic,
        });
        b.installArtifact(native_static_lib);
        b.installArtifact(native_shared_lib);
    }

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("kms_zig", root_mod);

    const unit_tests = b.addTest(.{
        .name = "kms-zig-tests",
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run zig unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
