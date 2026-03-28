const std = @import("std");
const smtp = @import("smtp");

/// Simple SMTP proxy that accepts connections and forwards mail to an upstream server.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const listen_port: u16 = 2525;
    const upstream_host = "127.0.0.1";
    const upstream_port: u16 = 25;

    const address = std.net.Address.parseIp("127.0.0.1", listen_port) catch unreachable;
    var tcp_server = try address.listen(.{});
    defer tcp_server.deinit();

    std.debug.print("SMTP proxy listening on port {d}, forwarding to {s}:{d}\n", .{ listen_port, upstream_host, upstream_port });

    while (true) {
        const connection = try tcp_server.accept();
        const stream_ptr = try allocator.create(std.net.Stream);
        stream_ptr.* = connection.stream;

        handleConnection(allocator, stream_ptr, upstream_host, upstream_port) catch |err| {
            std.debug.print("Proxy connection error: {any}\n", .{err});
        };
        allocator.destroy(stream_ptr);
    }
}

fn handleConnection(allocator: std.mem.Allocator, stream_ptr: *std.net.Stream, upstream_host: []const u8, upstream_port: u16) !void {
    const transport = smtp.wire.Transport.fromNetStream(stream_ptr);
    var reader = smtp.wire.LineReader.init(allocator, transport);

    // Send greeting
    try transport.print("220 smtp-proxy ready\r\n", .{});

    var from: ?[]u8 = null;
    defer if (from) |f| allocator.free(f);
    var recipients: std.ArrayList([]u8) = .empty;
    defer {
        for (recipients.items) |r| allocator.free(r);
        recipients.deinit(allocator);
    }

    while (true) {
        const line = reader.readLineAlloc() catch break;
        defer allocator.free(line);

        if (line.len < 4) {
            try transport.print("500 Command too short\r\n", .{});
            continue;
        }

        if (std.ascii.startsWithIgnoreCase(line, "EHLO") or std.ascii.startsWithIgnoreCase(line, "HELO")) {
            try transport.print("250-smtp-proxy\r\n250 OK\r\n", .{});
        } else if (std.ascii.startsWithIgnoreCase(line, "MAIL FROM:")) {
            if (from) |f| allocator.free(f);
            from = try allocator.dupe(u8, line[10..]);
            try transport.print("250 OK\r\n", .{});
        } else if (std.ascii.startsWithIgnoreCase(line, "RCPT TO:")) {
            try recipients.append(allocator, try allocator.dupe(u8, line[8..]));
            try transport.print("250 OK\r\n", .{});
        } else if (std.ascii.startsWithIgnoreCase(line, "DATA")) {
            try transport.print("354 Start mail input\r\n", .{});

            // Read message body until lone dot
            var body: std.ArrayList(u8) = .empty;
            defer body.deinit(allocator);
            while (true) {
                const data_line = reader.readLineAlloc() catch break;
                defer allocator.free(data_line);
                if (std.mem.eql(u8, data_line, ".")) break;
                // Un-dot-stuff
                if (data_line.len > 0 and data_line[0] == '.') {
                    try body.appendSlice(allocator, data_line[1..]);
                } else {
                    try body.appendSlice(allocator, data_line);
                }
                try body.appendSlice(allocator, "\r\n");
            }

            // Forward to upstream
            forwardMessage(allocator, upstream_host, upstream_port, from, recipients.items, body.items) catch |err| {
                std.debug.print("Forward error: {any}\n", .{err});
                try transport.print("451 Upstream delivery failed\r\n", .{});
                continue;
            };

            try transport.print("250 OK message forwarded\r\n", .{});

            // Reset for next message
            if (from) |f| allocator.free(f);
            from = null;
            for (recipients.items) |r| allocator.free(r);
            recipients.clearRetainingCapacity();
        } else if (std.ascii.startsWithIgnoreCase(line, "RSET")) {
            if (from) |f| allocator.free(f);
            from = null;
            for (recipients.items) |r| allocator.free(r);
            recipients.clearRetainingCapacity();
            try transport.print("250 OK\r\n", .{});
        } else if (std.ascii.startsWithIgnoreCase(line, "QUIT")) {
            try transport.print("221 Bye\r\n", .{});
            break;
        } else if (std.ascii.startsWithIgnoreCase(line, "NOOP")) {
            try transport.print("250 OK\r\n", .{});
        } else {
            try transport.print("502 Command not implemented\r\n", .{});
        }
    }
}

fn forwardMessage(allocator: std.mem.Allocator, host: []const u8, port: u16, from: ?[]u8, recipients: [][]u8, body: []u8) !void {
    var client = try smtp.client.Client.connectTcp(allocator, host, port);
    defer client.deinit();

    _ = try client.ehlo("smtp-proxy");

    const sender = if (from) |f| std.mem.trim(u8, f, " <>") else "postmaster@localhost";
    _ = try client.mailFrom(sender, .{});

    for (recipients) |rcpt| {
        const recipient = std.mem.trim(u8, rcpt, " <>");
        _ = try client.rcptTo(recipient, .{});
    }

    _ = try client.sendData(body);
    _ = try client.quit();
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    for (haystack[0..prefix.len], prefix) |h, p| {
        if (std.ascii.toLower(h) != std.ascii.toLower(p)) return false;
    }
    return true;
}
