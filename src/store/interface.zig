const std = @import("std");

/// Type-erased authentication backend interface.
pub const Backend = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        authenticate: *const fn (ctx: *anyopaque, username: []const u8, password: []const u8) ?bool,
        authenticate_external: *const fn (ctx: *anyopaque, username: []const u8) ?bool,
        authenticate_token: *const fn (ctx: *anyopaque, username: []const u8, token: []const u8) ?bool,
        add_user: *const fn (ctx: *anyopaque, username: []const u8, password: []const u8) anyerror!void,
    };

    pub fn authenticate(self: Backend, username: []const u8, password: []const u8) ?bool {
        return self.vtable.authenticate(self.context, username, password);
    }

    pub fn authenticateExternal(self: Backend, username: []const u8) ?bool {
        return self.vtable.authenticate_external(self.context, username);
    }

    pub fn authenticateToken(self: Backend, username: []const u8, token: []const u8) ?bool {
        return self.vtable.authenticate_token(self.context, username, token);
    }

    pub fn addUser(self: Backend, username: []const u8, password: []const u8) !void {
        return self.vtable.add_user(self.context, username, password);
    }

    /// Create a Backend from a concrete MemStore pointer.
    pub fn fromMemStore(store: anytype) Backend {
        const Ptr = @TypeOf(store);
        const Impl = struct {
            fn authenticateFn(ctx: *anyopaque, username: []const u8, password: []const u8) ?bool {
                const s: Ptr = @ptrCast(@alignCast(ctx));
                const result = s.authenticate(username, password);
                return if (result != null) true else null;
            }

            fn authenticateExternalFn(ctx: *anyopaque, username: []const u8) ?bool {
                const s: Ptr = @ptrCast(@alignCast(ctx));
                const result = s.authenticateExternal(username);
                return if (result != null) true else null;
            }

            fn authenticateTokenFn(ctx: *anyopaque, username: []const u8, token: []const u8) ?bool {
                const s: Ptr = @ptrCast(@alignCast(ctx));
                const result = s.authenticateToken(username, token);
                return if (result != null) true else null;
            }

            fn addUserFn(ctx: *anyopaque, username: []const u8, password: []const u8) anyerror!void {
                const s: Ptr = @ptrCast(@alignCast(ctx));
                try s.addUser(username, password);
            }
        };

        return .{
            .context = @ptrCast(store),
            .vtable = &.{
                .authenticate = Impl.authenticateFn,
                .authenticate_external = Impl.authenticateExternalFn,
                .authenticate_token = Impl.authenticateTokenFn,
                .add_user = Impl.addUserFn,
            },
        };
    }
};

/// Type-erased delivery backend interface.
pub const DeliveryBackend = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        deliver_message: *const fn (ctx: *anyopaque, from: []const u8, recipients: []const []u8, body: []const u8) anyerror!u32,
    };

    pub fn deliverMessage(self: DeliveryBackend, from: []const u8, recipients: []const []u8, body: []const u8) !u32 {
        return self.vtable.deliver_message(self.context, from, recipients, body);
    }

    /// Create a DeliveryBackend from a concrete MemStore pointer.
    pub fn fromMemStore(store: anytype) DeliveryBackend {
        const Ptr = @TypeOf(store);
        const Impl = struct {
            fn deliverFn(ctx: *anyopaque, from: []const u8, recipients: []const []u8, body: []const u8) anyerror!u32 {
                const s: Ptr = @ptrCast(@alignCast(ctx));
                return try s.deliverMessage(from, recipients, body);
            }
        };

        return .{
            .context = @ptrCast(store),
            .vtable = &.{
                .deliver_message = Impl.deliverFn,
            },
        };
    }
};
