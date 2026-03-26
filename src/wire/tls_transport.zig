const std = @import("std");
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;

const IoReader = std.Io.Reader;
const IoWriter = std.Io.Writer;

pub const TlsOptions = struct {
    host_verification: HostVerification = .no_verification,
    ca_verification: CaVerification = .no_verification,

    pub const HostVerification = union(enum) {
        no_verification,
        explicit: []const u8,
    };

    pub const CaVerification = union(enum) {
        no_verification,
        self_signed,
        bundle: std.crypto.Certificate.Bundle,
    };
};

pub const TlsTransport = struct {
    allocator: std.mem.Allocator,
    tls_client: *std.crypto.tls.Client,
    underlying_stream: std.net.Stream,
    // Owned buffers and I/O wrappers needed by the TLS client.
    net_reader: *std.net.Stream.Reader,
    net_writer: *std.net.Stream.Writer,
    read_buf: []u8,
    write_buf: []u8,
    tls_read_buf: []u8,
    tls_write_buf: []u8,

    const buffer_size = std.crypto.tls.max_ciphertext_record_len;

    pub fn init(
        allocator: std.mem.Allocator,
        underlying_stream: std.net.Stream,
        options: TlsOptions,
    ) !*TlsTransport {
        const self = try allocator.create(TlsTransport);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.underlying_stream = underlying_stream;

        // Allocate buffers for the stream Reader and Writer
        self.read_buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(self.read_buf);

        self.write_buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(self.write_buf);

        // Allocate buffers for the TLS client's own internal use
        self.tls_read_buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(self.tls_read_buf);

        self.tls_write_buf = try allocator.alloc(u8, buffer_size);
        errdefer allocator.free(self.tls_write_buf);

        // Create heap-allocated net.Stream Reader/Writer (self-referential, must be stable)
        self.net_reader = try allocator.create(std.net.Stream.Reader);
        errdefer allocator.destroy(self.net_reader);
        self.net_reader.* = underlying_stream.reader(self.read_buf);

        self.net_writer = try allocator.create(std.net.Stream.Writer);
        errdefer allocator.destroy(self.net_writer);
        self.net_writer.* = underlying_stream.writer(self.write_buf);

        // Build TLS host/ca options
        const tls_host: @TypeOf(@as(std.crypto.tls.Client.Options, undefined).host) = switch (options.host_verification) {
            .no_verification => .no_verification,
            .explicit => |h| .{ .explicit = h },
        };

        const tls_ca: @TypeOf(@as(std.crypto.tls.Client.Options, undefined).ca) = switch (options.ca_verification) {
            .no_verification => .no_verification,
            .self_signed => .self_signed,
            .bundle => |b| .{ .bundle = b },
        };

        self.tls_client = try allocator.create(std.crypto.tls.Client);
        errdefer allocator.destroy(self.tls_client);

        self.tls_client.* = std.crypto.tls.Client.init(
            self.net_reader.interface(),
            &self.net_writer.interface,
            .{
                .host = tls_host,
                .ca = tls_ca,
                .read_buffer = self.tls_read_buf,
                .write_buffer = self.tls_write_buf,
            },
        ) catch return error.TlsInitError;

        return self;
    }

    pub fn transport(self: *TlsTransport) Transport {
        return .{
            .context = @ptrCast(self),
            .read_fn = tlsRead,
            .write_fn = tlsWrite,
            .close_fn = tlsClose,
        };
    }

    pub fn deinit(self: *TlsTransport) void {
        const allocator = self.allocator;
        allocator.destroy(self.tls_client);
        allocator.destroy(self.net_reader);
        allocator.destroy(self.net_writer);
        allocator.free(self.read_buf);
        allocator.free(self.write_buf);
        allocator.free(self.tls_read_buf);
        allocator.free(self.tls_write_buf);
        allocator.destroy(self);
    }

    pub fn deinitAndClose(self: *TlsTransport) void {
        const stream = self.underlying_stream;
        self.deinit();
        stream.close();
    }

    fn tlsRead(context: *anyopaque, buffer: []u8) Transport.ReadError!usize {
        const self: *TlsTransport = @ptrCast(@alignCast(context));
        const data = self.tls_client.reader.take(buffer.len) catch return error.Unexpected;
        @memcpy(buffer[0..data.len], data);
        return data.len;
    }

    fn tlsWrite(context: *anyopaque, buffer: []const u8) Transport.WriteError!usize {
        const self: *TlsTransport = @ptrCast(@alignCast(context));
        self.tls_client.writer.writeAll(buffer) catch return error.Unexpected;
        return buffer.len;
    }

    fn tlsClose(context: *anyopaque) void {
        const self: *TlsTransport = @ptrCast(@alignCast(context));
        self.deinitAndClose();
    }
};
