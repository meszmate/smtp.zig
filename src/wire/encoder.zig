const std = @import("std");

pub const Encoder = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) Encoder {
        return .{
            .allocator = allocator,
            .bytes = .empty,
        };
    }

    pub fn deinit(self: *Encoder) void {
        self.bytes.deinit(self.allocator);
    }

    pub fn clear(self: *Encoder) void {
        self.bytes.clearRetainingCapacity();
    }

    /// Writes a raw atom string (unquoted).
    pub fn atom(self: *Encoder, s: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, s);
    }

    /// Writes a single space character.
    pub fn sp(self: *Encoder) !void {
        try self.bytes.append(self.allocator, ' ');
    }

    /// Writes a CRLF line terminator.
    pub fn crlf(self: *Encoder) !void {
        try self.bytes.appendSlice(self.allocator, "\r\n");
    }

    /// Writes raw bytes into the buffer.
    pub fn writeAll(self: *Encoder, data: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, data);
    }

    /// Returns the accumulated bytes as a slice and resets the encoder.
    /// Caller owns the returned memory.
    pub fn finish(self: *Encoder) ![]u8 {
        return self.bytes.toOwnedSlice(self.allocator);
    }

    // ---- SMTP-specific methods ----

    /// Writes an SMTP command name (e.g., "EHLO", "MAIL FROM").
    pub fn command(self: *Encoder, name: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, name);
    }

    /// Writes a parameter in the form " KEY=VALUE".
    pub fn param(self: *Encoder, key: []const u8, value: []const u8) !void {
        try self.bytes.append(self.allocator, ' ');
        try self.bytes.appendSlice(self.allocator, key);
        try self.bytes.append(self.allocator, '=');
        try self.bytes.appendSlice(self.allocator, value);
    }

    /// Writes an address enclosed in angle brackets: "<addr>".
    pub fn angleBracket(self: *Encoder, addr: []const u8) !void {
        try self.bytes.append(self.allocator, '<');
        try self.bytes.appendSlice(self.allocator, addr);
        try self.bytes.append(self.allocator, '>');
    }

    /// Applies dot-stuffing to message body data for the DATA command.
    /// Per RFC 5321, any line in the message body that starts with a '.'
    /// must have an additional '.' prepended.
    pub fn dotStuff(self: *Encoder, data: []const u8) !void {
        var start: usize = 0;
        var at_line_start = true;

        for (data, 0..) |byte, i| {
            if (at_line_start and byte == '.') {
                // Write everything up to this point, then insert the extra dot
                try self.bytes.appendSlice(self.allocator, data[start..i]);
                try self.bytes.append(self.allocator, '.');
                start = i;
                at_line_start = false;
            } else if (byte == '\n') {
                at_line_start = true;
            } else {
                at_line_start = false;
            }
        }

        // Write remaining data
        if (start < data.len) {
            try self.bytes.appendSlice(self.allocator, data[start..]);
        }
    }

    /// Writes the DATA command terminator sequence: ".\r\n".
    pub fn dataTerminator(self: *Encoder) !void {
        try self.bytes.appendSlice(self.allocator, ".\r\n");
    }

    /// Base64-encodes the given data and appends it to the buffer.
    pub fn base64(self: *Encoder, data: []const u8) !void {
        const base64_encoder = std.base64.standard.Encoder;
        const encoded_len = base64_encoder.calcSize(data.len);

        try self.bytes.ensureUnusedCapacity(self.allocator, encoded_len);
        const dest = self.bytes.unusedCapacitySlice();
        _ = base64_encoder.encode(dest[0..encoded_len], data);
        self.bytes.items.len += encoded_len;
    }
};
