const builtin = @import("builtin");

pub usingnamespace switch (builtin.zig_backend) {
    .stage1 => @cImport({
        @cInclude("uv.h");
    }),

    // Workaround for:
    // https://github.com/ziglang/zig/issues/12325
    //
    // Generated by:
    // zig translate-c -target aarch64-macos -lc -Ivendor/libuv/include vendor/libuv/include/uv.h
    // (and then manually modified)
    else => switch (builtin.os.tag) {
        .macos => @import("cimport_macos.zig"),
        .linux => @import("cimport_linux.zig"),
        else => @compileError("unsupported OS for now, see this line"),
    },
};
