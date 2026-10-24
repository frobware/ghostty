//! Kitty clipboard protocol (OSC 5522) response encoding.

const std = @import("std");
const clipboard = @import("../clipboard.zig");
const oscpkg = @import("../osc.zig");
const protocol = @import("../osc/parsers/kitty_clipboard_protocol.zig");

const b64 = std.base64.standard.Encoder;
const Content = clipboard.Content;
const Operation = protocol.Operation;
const Status = protocol.Status;
const Terminator = oscpkg.Terminator;

/// Saturating size arithmetic lets admission reject even a reply whose
/// base64 expansion cannot be represented by usize.
pub fn base64Size(len: usize) usize {
    return (len / 3) *| 4 +| (if (len % 3 > 0) @as(usize, 4) else 0);
}

/// Maximum raw (pre-base64) bytes per DATA packet in read responses.
/// This is specified by the protocol.
pub const read_chunk_size = 4096;

/// Maximum requested MIME types served by a single read request.
/// Requests beyond this simply see no DATA packets for the extras,
/// which is how the protocol communicates an unavailable type anyway.
pub const max_read_mimes = 4;

/// The special MIME type that requests the list of available types.
pub const targets_mime = ".";

/// Maximum MIME types reported in a paste event's targets listing.
pub const max_listing_mimes = 16;

/// A single response packet.
pub const Response = struct {
    op: Operation,
    status: Status,
    primary: bool = false,
    id: []const u8 = "",
    mime: ?[]const u8 = null,
    pw: ?[]const u8 = null,
    /// The raw payload; the encoder base64-encodes it. An empty payload
    /// emits no payload section at all (no ';').
    payload: []const u8 = "",
    terminator: Terminator = .st,

    /// Size without reading or encoding the payload. Metadata is bounded by
    /// the protocol and is counted through the same encoder as actual output.
    pub fn encodedSize(self: *const Response) usize {
        var count: std.Io.Writer.Discarding = .init(&.{});
        self.encodeMetadata(&count.writer) catch unreachable;
        var len: usize = @intCast(count.fullCount());
        if (self.payload.len > 0) len = len +| 1 +| base64Size(self.payload.len);
        return len +| self.terminator.string().len;
    }

    /// Encode the response. Errors may result in partially written data
    /// so it is up to callers to buffer it if they need to.
    pub fn encode(
        self: *const Response,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try self.encodeMetadata(writer);
        if (self.payload.len > 0) {
            try writer.writeAll(";");
            try b64.encodeWriter(writer, self.payload);
        }
        try writer.writeAll(self.terminator.string());
    }

    /// Encode the escape prefix and metadata section only: everything
    /// up to (and not including) the payload section and terminator.
    fn encodeMetadata(
        self: *const Response,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        // The exact order of fields here matches what Kitty does.
        try writer.print("\x1b]5522;type={t}:status={t}", .{ self.op, self.status });
        if (self.primary) try writer.writeAll(":loc=primary");
        if (self.id.len > 0) try writer.print(":id={s}", .{self.id});
        if (self.mime) |mime| {
            try writer.writeAll(":mime=");
            try b64.encodeWriter(writer, mime);
        }
        if (self.pw) |pw| {
            try writer.writeAll(":pw=");
            try b64.encodeWriter(writer, pw);
        }
    }
};

/// Encode a full successful read response: the OK packet, the targets
/// listing if requested, DATA chunks for each served representation,
/// and the final DONE packet. This is also the shape of an unsolicited
/// paste event (list=true, pw set to the one-time password).
pub const ReadSuccess = struct {
    primary: bool = false,
    id: []const u8 = "",

    /// One-time password echoed in every packet. Only used for
    /// terminal-initiated paste events.
    pw: ?[]const u8 = null,

    /// True when the targets ('.') listing was requested.
    list: bool = false,

    /// The MIME types available on the clipboard, reported by the
    /// targets listing. Kitty reports these space-separated in one
    /// packet with a trailing newline when non-empty.
    available: []const []const u8 = &.{},

    /// The representations to serve, in request order. Each entry's
    /// data is chunked into DATA packets under its own MIME type. An
    /// entry with empty data produces no packets, which is how the
    /// protocol communicates an unavailable type.
    contents: []const Content = &.{},

    terminator: Terminator = .st,

    /// Measure the whole success sequence before allocating or encoding any
    /// clipboard contents. Chunk counts are arithmetic, independent of data.
    pub fn encodedSize(self: *const ReadSuccess) usize {
        var len = (Response{
            .op = .read,
            .status = .OK,
            .primary = self.primary,
            .id = self.id,
            .pw = self.pw,
            .terminator = self.terminator,
        }).encodedSize();
        if (self.list) {
            // The listing has a fixed 4096-byte raw bound, independent of
            // the representation data being measured.
            var count: std.Io.Writer.Discarding = .init(&.{});
            self.encodeListing(&count.writer) catch unreachable;
            len +|= @intCast(count.fullCount());
        }
        for (self.contents) |content| {
            const header = (Response{
                .op = .read,
                .status = .DATA,
                .id = self.id,
                .mime = content.mime,
                .pw = self.pw,
                .terminator = self.terminator,
            }).encodedSize() +| 1;
            const full = content.data.len / read_chunk_size;
            const tail = content.data.len % read_chunk_size;
            len +|= full *| (header +| base64Size(read_chunk_size));
            if (tail > 0) len = len +| header +| base64Size(tail);
        }
        return len +| (Response{
            .op = .read,
            .status = .DONE,
            .id = self.id,
            .pw = self.pw,
            .terminator = self.terminator,
        }).encodedSize();
    }

    pub fn encode(
        self: *const ReadSuccess,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        // Initial read response
        try (Response{
            .op = .read,
            .status = .OK,
            .primary = self.primary,
            .id = self.id,
            .pw = self.pw,
            .terminator = self.terminator,
        }).encode(writer);

        // Listing of mimes if requested
        if (self.list) try self.encodeListing(writer);

        // Encoding of each mime-type + content
        for (self.contents) |content| {
            var i: usize = 0;
            while (i < content.data.len) {
                const n = @min(content.data.len - i, read_chunk_size);
                try (Response{
                    .op = .read,
                    .status = .DATA,
                    .id = self.id,
                    .mime = content.mime,
                    .pw = self.pw,
                    .payload = content.data[i..][0..n],
                    .terminator = self.terminator,
                }).encode(writer);
                i += n;
            }
        }

        // Trailing done.
        try (Response{
            .op = .read,
            .status = .DONE,
            .id = self.id,
            .pw = self.pw,
            .terminator = self.terminator,
        }).encode(writer);
    }

    /// Encode the targets ('.') listing packet. The listing gets a
    /// trailing newline when non-empty.
    fn encodeListing(
        self: *const ReadSuccess,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const listing: Response = .{
            .op = .read,
            .status = .DATA,
            .id = self.id,
            .mime = targets_mime,
            .pw = self.pw,
            .terminator = self.terminator,
        };
        try listing.encodeMetadata(writer);
        if (self.available.len > 0) {
            try writer.writeAll(";");

            // Join the types into one chunk before encoding. The
            // listing is a DATA packet, so it shares the pre-encoding
            // chunk size bound of any other data packet; types that
            // don't fit are dropped (a listing that large doesn't
            // happen in practice).
            var raw: [read_chunk_size]u8 = undefined;
            var fixed: std.Io.Writer = .fixed(&raw);
            for (self.available, 0..) |mime, i| {
                const sep: usize = if (i > 0) 1 else 0;
                if (fixed.end + sep + mime.len + "\n".len > raw.len) break;
                if (i > 0) fixed.writeAll(" ") catch unreachable;
                fixed.writeAll(mime) catch unreachable;
            }
            fixed.writeAll("\n") catch unreachable;
            try b64.encodeWriter(writer, fixed.buffered());
        }
        try writer.writeAll(self.terminator.string());
    }
};

/// An unsolicited Kitty paste event (mode 5522): a read response that
/// lists the clipboard's available MIME types and carries the one-time
/// password the program uses for its follow-up read.
pub const PasteEvent = struct {
    /// True if the paste came from the primary selection, reported as
    /// `loc=primary` on the OK packet.
    primary: bool = false,

    /// The one-time password, echoed in every packet.
    pw: []const u8,

    /// The MIME types available on the clipboard.
    available: []const []const u8,

    terminator: Terminator = .st,

    pub fn encode(
        self: *const PasteEvent,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try (ReadSuccess{
            .primary = self.primary,
            .pw = self.pw,
            .list = true,
            .available = self.available,
            .terminator = self.terminator,
        }).encode(writer);
    }
};

test "clipboard reply size matches encoded chunking and metadata" {
    const testing = std.testing;
    var data: [2 * read_chunk_size + 1]u8 = @splat('x');
    const long_id: [512]u8 = @splat('x');
    var output: [32 * 1024]u8 = undefined;
    for ([_]usize{ 0, 1, 2, 3, read_chunk_size - 1, read_chunk_size, read_chunk_size + 1, data.len }) |len| {
        for ([_]Terminator{ .bel, .st }) |terminator| {
            for ([_]bool{ false, true }) |list| {
                const response: ReadSuccess = .{
                    .primary = true,
                    .id = &long_id,
                    .pw = "password",
                    .list = list,
                    .available = &.{ "text/plain", "image/png" },
                    .contents = &.{
                        .{ .mime = "text/plain", .data = data[0..len] },
                        .{ .mime = "image/png", .data = data[0..len] },
                    },
                    .terminator = terminator,
                };
                var writer: std.Io.Writer = .fixed(&output);
                try response.encode(&writer);
                try testing.expectEqual(writer.buffered().len, response.encodedSize());
            }
        }
    }

    // Listings drop types which exceed the fixed raw listing buffer. Size
    // measurement must follow that same truncation, including empty lists.
    const long_type: [read_chunk_size]u8 = @splat('x');
    for ([_][]const []const u8{ &.{}, &.{ "text/plain", &long_type, "image/png" } }) |available| {
        const response: ReadSuccess = .{ .list = true, .available = available };
        var writer: std.Io.Writer = .fixed(&output);
        try response.encode(&writer);
        try testing.expectEqual(writer.buffered().len, response.encodedSize());
    }
}

test "clipboard reply size saturates without reading representation data" {
    const testing = std.testing;
    // Deliberately unreadable: measuring only needs a representation length.
    const data: []const u8 = @as([*]const u8, @ptrFromInt(1))[0..std.math.maxInt(usize)];
    try testing.expectEqual(std.math.maxInt(usize), base64Size(data.len));
    try testing.expectEqual(std.math.maxInt(usize), (Response{
        .op = .read,
        .status = .DATA,
        .payload = data,
    }).encodedSize());
    try testing.expectEqual(std.math.maxInt(usize), (ReadSuccess{
        .contents = &.{.{ .mime = "text/plain", .data = data }},
    }).encodedSize());
}

test "response: basic status packet" {
    const testing = std.testing;

    var buf: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (Response{ .op = .write, .status = .DONE }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=write:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "response: id echo and terminator" {
    const testing = std.testing;

    var buf: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (Response{
        .op = .write,
        .status = .EPERM,
        .id = "42",
        .terminator = .bel,
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=write:status=EPERM:id=42\x07",
        writer.buffered(),
    );
}

test "response: key order type,status,loc,id,mime,pw and payload" {
    const testing = std.testing;

    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (Response{
        .op = .read,
        .status = .DATA,
        .primary = true,
        .id = "x",
        .mime = "text/plain",
        .pw = "otp",
        .payload = "Ghostty",
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=DATA:loc=primary:id=x" ++
            ":mime=dGV4dC9wbGFpbg==:pw=b3Rw;R2hvc3R0eQ==\x1b\\",
        writer.buffered(),
    );
}

test "read success: empty request is OK then DONE" {
    const testing = std.testing;

    var buf: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{ .id = "7" }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK:id=7\x1b\\" ++
            "\x1b]5522;type=read:status=DONE:id=7\x1b\\",
        writer.buffered(),
    );
}

test "read success: targets listing with text" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{ .list = true, .available = &.{"text/plain"} }).encode(&writer);
    // "." => "Lg==", "text/plain\n" => "dGV4dC9wbGFpbgo="
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==;dGV4dC9wbGFpbgo=\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: targets listing joins multiple types" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{
        .list = true,
        .available = &.{ "text/plain", "image/png" },
    }).encode(&writer);
    // Payload is base64 of "text/plain image/png\n".
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==;dGV4dC9wbGFpbiBpbWFnZS9wbmcK\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: empty targets listing packet still sent" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{ .list = true }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: data chunks under requested mime" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{
        .contents = &.{.{ .mime = "text/plain", .data = "Ghostty" }},
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=dGV4dC9wbGFpbg==;R2hvc3R0eQ==\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: each representation carries its own data" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{
        .contents = &.{
            .{ .mime = "text/plain", .data = "hello" },
            .{ .mime = "image/png", .data = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a" },
        },
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=dGV4dC9wbGFpbg==;aGVsbG8=\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=aW1hZ2UvcG5n;iVBORw0KGgo=\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: chunking at read_chunk_size" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const data: [read_chunk_size + 1]u8 = @splat('z');
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();
    try (ReadSuccess{
        .contents = &.{.{ .mime = "text/plain", .data = &data }},
    }).encode(&aw.writer);

    // OK + 2 DATA packets + DONE = 4 packets.
    const count = std.mem.count(u8, aw.written(), "\x1b]5522;");
    try testing.expectEqual(@as(usize, 4), count);

    // The first chunk is exactly read_chunk_size bytes, base64 encoded
    // with padding.
    const Encoder = std.base64.standard.Encoder;
    var chunk_buf: [Encoder.calcSize(read_chunk_size)]u8 = undefined;
    const first = Encoder.encode(&chunk_buf, data[0..read_chunk_size]);
    try testing.expect(std.mem.indexOf(u8, aw.written(), first) != null);
}

test "read success: no data packets for empty clipboard" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{
        .contents = &.{.{ .mime = "text/plain", .data = "" }},
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK\x1b\\" ++
            "\x1b]5522;type=read:status=DONE\x1b\\",
        writer.buffered(),
    );
}

test "read success: paste event carries pw in every packet" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (ReadSuccess{
        .list = true,
        .pw = "otp",
        .available = &.{"text/plain"},
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK:pw=b3Rw\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==:pw=b3Rw;dGV4dC9wbGFpbgo=\x1b\\" ++
            "\x1b]5522;type=read:status=DONE:pw=b3Rw\x1b\\",
        writer.buffered(),
    );
}

test "paste event: pw in every packet, listing of every type" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (PasteEvent{
        .pw = "otp",
        .available = &.{ "text/plain", "image/png" },
    }).encode(&writer);
    // Payload is base64 of "text/plain image/png\n".
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK:pw=b3Rw\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==:pw=b3Rw;dGV4dC9wbGFpbiBpbWFnZS9wbmcK\x1b\\" ++
            "\x1b]5522;type=read:status=DONE:pw=b3Rw\x1b\\",
        writer.buffered(),
    );
}

test "paste event: primary is reported only on the OK packet" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (PasteEvent{
        .primary = true,
        .pw = "otp",
        .available = &.{"text/plain"},
        .terminator = .bel,
    }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK:loc=primary:pw=b3Rw\x07" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==:pw=b3Rw;dGV4dC9wbGFpbgo=\x07" ++
            "\x1b]5522;type=read:status=DONE:pw=b3Rw\x07",
        writer.buffered(),
    );
}

test "paste event: empty listing packet is still sent" {
    const testing = std.testing;

    var buf: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try (PasteEvent{ .pw = "otp", .available = &.{} }).encode(&writer);
    try testing.expectEqualStrings(
        "\x1b]5522;type=read:status=OK:pw=b3Rw\x1b\\" ++
            "\x1b]5522;type=read:status=DATA:mime=Lg==:pw=b3Rw\x1b\\" ++
            "\x1b]5522;type=read:status=DONE:pw=b3Rw\x1b\\",
        writer.buffered(),
    );
}
