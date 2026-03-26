const std = @import("std");
const conn_mod = @import("conn.zig");

const Conn = conn_mod.Conn;
const Command = conn_mod.Command;

/// Context passed to command handlers.
pub const CommandContext = struct {
    /// The connection being served.
    conn: *Conn,
    /// The parsed command.
    command: Command,
    /// Raw command line (owned by caller).
    raw: []u8,
    /// Optional user data.
    user_data: ?*anyopaque = null,
};

/// Function signature for command handlers.
pub const CommandHandlerFn = *const fn (ctx: *CommandContext) anyerror!void;

/// Routes SMTP commands to handler functions, with optional middleware wrapping.
pub const Dispatcher = struct {
    allocator: std.mem.Allocator,
    handlers: std.StringHashMap(CommandHandlerFn),
    middleware: ?*const fn (handler: CommandHandlerFn) CommandHandlerFn = null,
    fallback: ?CommandHandlerFn = null,

    pub fn init(allocator: std.mem.Allocator) Dispatcher {
        return .{
            .allocator = allocator,
            .handlers = std.StringHashMap(CommandHandlerFn).init(allocator),
        };
    }

    pub fn deinit(self: *Dispatcher) void {
        self.handlers.deinit();
    }

    /// Register a handler for a specific command verb.
    pub fn register(self: *Dispatcher, verb: []const u8, handler: CommandHandlerFn) !void {
        try self.handlers.put(verb, handler);
    }

    /// Set the middleware wrapper function.
    pub fn setMiddleware(self: *Dispatcher, mw: *const fn (handler: CommandHandlerFn) CommandHandlerFn) void {
        self.middleware = mw;
    }

    /// Set the fallback handler for unrecognized commands.
    pub fn setFallback(self: *Dispatcher, handler: CommandHandlerFn) void {
        self.fallback = handler;
    }

    /// Dispatch a command to the appropriate handler.
    pub fn dispatch(self: *Dispatcher, ctx: *CommandContext) !void {
        // Normalize the verb to uppercase for lookup.
        var upper_buf: [64]u8 = undefined;
        const verb_len = @min(ctx.command.verb.len, upper_buf.len);
        for (ctx.command.verb[0..verb_len], 0..) |c, i| {
            upper_buf[i] = std.ascii.toUpper(c);
        }
        const upper_verb = upper_buf[0..verb_len];

        if (self.handlers.get(upper_verb)) |handler| {
            const effective = if (self.middleware) |mw| mw(handler) else handler;
            try effective(ctx);
        } else if (self.fallback) |fb| {
            try fb(ctx);
        } else {
            try ctx.conn.writeError(502, "5.5.1 Command not recognized");
        }
    }
};
