const std = @import("std");
const smtp = @import("smtp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Connect to an SMTP server
    var client = try smtp.client.Client.connectTcp(allocator, "127.0.0.1", 2525);
    defer client.deinit();

    // Send EHLO
    _ = try client.ehlo("localhost");

    // Authenticate if needed
    // try client.authenticatePlain("user", "password");

    // Send an email
    _ = try client.sendMail(
        "sender@example.com",
        &.{"recipient@example.com"},
        "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello, World!\r\n",
    );

    // Quit
    _ = try client.quit();
}
