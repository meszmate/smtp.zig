const std = @import("std");
const smtp = @import("smtp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create an in-memory store
    var store = smtp.store.MemStore.init(allocator);
    defer store.deinit();

    // Add a test user
    try store.addUser("user@example.com", "password");

    // Create and configure the server
    var server = smtp.server.Server.init(allocator, &store);

    // Listen on port 2525
    const address = std.net.Address.parseIp("127.0.0.1", 2525) catch unreachable;
    var tcp_server = try address.listen(.{});
    defer tcp_server.deinit();

    std.debug.print("SMTP server listening on port 2525\n", .{});

    while (true) {
        const connection = try tcp_server.accept();
        const stream_ptr = try allocator.create(std.net.Stream);
        stream_ptr.* = connection.stream;

        const transport = smtp.wire.Transport.fromNetStream(stream_ptr);
        server.serveConnection(transport, stream_ptr.*, false);
        allocator.destroy(stream_ptr);
    }
}
