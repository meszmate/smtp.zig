const std = @import("std");
const transport_mod = @import("transport.zig");
const Transport = transport_mod.Transport;

pub const LineReader = struct {
    allocator: std.mem.Allocator,
    transport_layer: Transport,
    max_line_length: usize = std.math.maxInt(usize),

    pub fn init(allocator: std.mem.Allocator, transport_layer: Transport) LineReader {
        return .{
            .allocator = allocator,
            .transport_layer = transport_layer,
        };
    }

    /// Reads until a newline character is encountered.
    /// Returns the line with trailing \r and \n stripped.
    /// Caller owns the returned memory.
    pub fn readLineAlloc(self: *LineReader) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        while (true) {
            var buf: [1]u8 = undefined;
            const n = try self.transport_layer.read(&buf);
            if (n == 0) {
                if (result.items.len == 0) {
                    result.deinit(self.allocator);
                    return error.EndOfStream;
                }
                break;
            }

            const byte = buf[0];
            if (byte == '\n') {
                // Strip trailing \r if present
                if (result.items.len > 0 and result.items[result.items.len - 1] == '\r') {
                    _ = result.pop();
                }
                break;
            }

            if (result.items.len >= self.max_line_length) {
                return error.LineTooLong;
            }
            try result.append(self.allocator, byte);
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Reads exactly `len` bytes from the transport.
    /// Caller owns the returned memory.
    pub fn readExactAlloc(self: *LineReader, len: usize) ![]u8 {
        const buf = try self.allocator.alloc(u8, len);
        errdefer self.allocator.free(buf);

        var total_read: usize = 0;
        while (total_read < len) {
            const n = try self.transport_layer.read(buf[total_read..]);
            if (n == 0) return error.EndOfStream;
            total_read += n;
        }

        return buf;
    }

    /// Reads and validates a CRLF (\r\n) terminator sequence.
    /// Returns an error if the next two bytes are not \r\n.
    pub fn readCrlf(self: *LineReader) !void {
        var buf: [2]u8 = undefined;
        var total_read: usize = 0;

        while (total_read < 2) {
            const n = try self.transport_layer.read(buf[total_read..]);
            if (n == 0) return error.EndOfStream;
            total_read += n;
        }

        if (buf[0] != '\r' or buf[1] != '\n') {
            return error.ExpectedCrlf;
        }
    }
};
