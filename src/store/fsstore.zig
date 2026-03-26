const std = @import("std");

pub const FsStore = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,

    pub fn init(allocator: std.mem.Allocator, root_path: []const u8) !FsStore {
        var cwd = std.fs.cwd();
        try cwd.makePath(root_path);
        const users_path = try std.fs.path.join(allocator, &.{ root_path, "users" });
        defer allocator.free(users_path);
        try cwd.makePath(users_path);
        return .{
            .allocator = allocator,
            .root_path = try allocator.dupe(u8, root_path),
        };
    }

    pub fn deinit(self: *FsStore) void {
        self.allocator.free(self.root_path);
    }

    pub fn addUser(self: *FsStore, username: []const u8, password: []const u8) !void {
        const user_dir = try self.userDirAlloc(username);
        defer self.allocator.free(user_dir);
        try std.fs.cwd().makePath(user_dir);
        const password_path = try std.fs.path.join(self.allocator, &.{ user_dir, "password.txt" });
        defer self.allocator.free(password_path);
        try writeFileLocal(password_path, password);

        try self.createMaildir(username);
    }

    pub fn authenticate(self: *FsStore, username: []const u8, password: []const u8) !FsUser {
        const password_path = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", username, "password.txt" });
        defer self.allocator.free(password_path);
        const actual = try std.fs.cwd().readFileAlloc(self.allocator, password_path, 1024 * 16);
        defer self.allocator.free(actual);
        if (!std.mem.eql(u8, std.mem.trimRight(u8, actual, "\r\n"), password)) return error.InvalidCredentials;
        return .{
            .allocator = self.allocator,
            .root_path = self.root_path,
            .username = try self.allocator.dupe(u8, username),
        };
    }

    /// Ensure the maildir structure exists for a user (new, cur, tmp subdirectories).
    pub fn createMaildir(self: *FsStore, username: []const u8) !void {
        const maildir_path = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", username, "maildir" });
        defer self.allocator.free(maildir_path);
        try std.fs.cwd().makePath(maildir_path);

        const new_path = try std.fs.path.join(self.allocator, &.{ maildir_path, "new" });
        defer self.allocator.free(new_path);
        try std.fs.cwd().makePath(new_path);

        const cur_path = try std.fs.path.join(self.allocator, &.{ maildir_path, "cur" });
        defer self.allocator.free(cur_path);
        try std.fs.cwd().makePath(cur_path);

        const tmp_path = try std.fs.path.join(self.allocator, &.{ maildir_path, "tmp" });
        defer self.allocator.free(tmp_path);
        try std.fs.cwd().makePath(tmp_path);
    }

    /// Deliver a message to a user's maildir.
    /// Returns the number of successful deliveries (0 or 1 per recipient).
    pub fn deliverMessage(self: *FsStore, from: []const u8, recipients: []const []u8, body: []const u8) !u32 {
        var delivered: u32 = 0;
        for (recipients) |rcpt| {
            const local = extractLocal(rcpt);
            // Check if user exists by checking their directory
            const user_dir = try self.userDirAlloc(local);
            defer self.allocator.free(user_dir);
            var dir = std.fs.cwd().openDir(user_dir, .{}) catch continue;
            dir.close();

            // Build message content with headers
            var content: std.ArrayList(u8) = .empty;
            defer content.deinit(self.allocator);
            try content.appendSlice(self.allocator, "From: ");
            try content.appendSlice(self.allocator, from);
            try content.appendSlice(self.allocator, "\r\nTo: ");
            for (recipients, 0..) |r, i| {
                if (i != 0) try content.appendSlice(self.allocator, ", ");
                try content.appendSlice(self.allocator, r);
            }
            try content.appendSlice(self.allocator, "\r\n\r\n");
            try content.appendSlice(self.allocator, body);

            // Generate unique filename based on timestamp
            const timestamp: u64 = @intCast(std.time.timestamp());
            const sanitized_local = try sanitizeAlloc(self.allocator, local);
            defer self.allocator.free(sanitized_local);
            const msg_name = try std.fmt.allocPrint(self.allocator, "{d}_{s}.eml", .{ timestamp, sanitized_local });
            defer self.allocator.free(msg_name);
            const msg_path = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", local, "maildir", "new", msg_name });
            defer self.allocator.free(msg_path);
            try writeFileLocal(msg_path, content.items);
            delivered += 1;
        }
        return delivered;
    }

    fn userDirAlloc(self: *FsStore, username: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.root_path, "users", username });
    }

    fn extractLocal(addr: []const u8) []const u8 {
        if (std.mem.indexOfScalar(u8, addr, '@')) |idx| {
            return addr[0..idx];
        }
        return addr;
    }
};

pub const FsUser = struct {
    allocator: std.mem.Allocator,
    root_path: []const u8,
    username: []u8,

    pub fn deinit(self: *FsUser) void {
        self.allocator.free(self.username);
    }

    /// Append a message to the user's maildir/new directory.
    pub fn appendMessage(self: *FsUser, from: []const u8, recipients_text: []const u8, body: []const u8) !void {
        const maildir_new = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", self.username, "maildir", "new" });
        defer self.allocator.free(maildir_new);
        try std.fs.cwd().makePath(maildir_new);

        // Build message content
        var content: std.ArrayList(u8) = .empty;
        defer content.deinit(self.allocator);
        try content.appendSlice(self.allocator, "From: ");
        try content.appendSlice(self.allocator, from);
        try content.appendSlice(self.allocator, "\r\nTo: ");
        try content.appendSlice(self.allocator, recipients_text);
        try content.appendSlice(self.allocator, "\r\n\r\n");
        try content.appendSlice(self.allocator, body);

        // Generate unique filename
        const timestamp: u64 = @intCast(std.time.timestamp());
        const msg_name = try std.fmt.allocPrint(self.allocator, "{d}.eml", .{timestamp});
        defer self.allocator.free(msg_name);
        const msg_path = try std.fs.path.join(self.allocator, &.{ maildir_new, msg_name });
        defer self.allocator.free(msg_path);
        try writeFileLocal(msg_path, content.items);
    }

    /// List message filenames in the user's maildir/new directory.
    pub fn listMessagesAlloc(self: *FsUser) ![][]u8 {
        const maildir_new = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", self.username, "maildir", "new" });
        defer self.allocator.free(maildir_new);
        var dir = std.fs.cwd().openDir(maildir_new, .{ .iterate = true }) catch return try self.allocator.alloc([]u8, 0);
        defer dir.close();

        var list: std.ArrayList([]u8) = .empty;
        errdefer {
            for (list.items) |item| self.allocator.free(item);
            list.deinit(self.allocator);
        }
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            try list.append(self.allocator, try self.allocator.dupe(u8, entry.name));
        }
        return list.toOwnedSlice(self.allocator);
    }

    /// Read the contents of a message file.
    pub fn readMessageAlloc(self: *FsUser, filename: []const u8) ![]u8 {
        const msg_path = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", self.username, "maildir", "new", filename });
        defer self.allocator.free(msg_path);
        return std.fs.cwd().readFileAlloc(self.allocator, msg_path, 1024 * 1024 * 10);
    }

    /// Delete a message file.
    pub fn deleteMessage(self: *FsUser, filename: []const u8) !void {
        const msg_path = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", self.username, "maildir", "new", filename });
        defer self.allocator.free(msg_path);
        std.fs.cwd().deleteFile(msg_path) catch |err| switch (err) {
            error.FileNotFound => return error.NoSuchMessage,
            else => return err,
        };
    }

    /// Get the number of messages in the user's maildir/new directory.
    pub fn getMessageCount(self: *FsUser) !u32 {
        const maildir_new = try std.fs.path.join(self.allocator, &.{ self.root_path, "users", self.username, "maildir", "new" });
        defer self.allocator.free(maildir_new);
        var dir = std.fs.cwd().openDir(maildir_new, .{ .iterate = true }) catch return 0;
        defer dir.close();
        var count: u32 = 0;
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".eml")) count += 1;
        }
        return count;
    }
};

fn writeFileLocal(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
}

fn sanitizeAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (value) |byte| {
        try out.append(allocator, if (byte == '/' or byte == '\\' or byte == '@') '_' else byte);
    }
    return out.toOwnedSlice(allocator);
}
