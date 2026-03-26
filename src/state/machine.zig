const std = @import("std");
const types = @import("../root.zig");

pub const ConnState = types.ConnState;

pub const TransitionHook = *const fn (ConnState, ConnState) anyerror!void;

pub const TransitionSpec = struct {
    from: ConnState,
    allowed: []const ConnState,
};

pub const Machine = struct {
    allocator: std.mem.Allocator,
    state: ConnState,
    transitions: std.AutoHashMap(ConnState, []const ConnState),
    before_hooks: std.ArrayList(TransitionHook),
    after_hooks: std.ArrayList(TransitionHook),

    pub fn init(allocator: std.mem.Allocator, initial: ConnState) Machine {
        var m = Machine{
            .allocator = allocator,
            .state = initial,
            .transitions = std.AutoHashMap(ConnState, []const ConnState).init(allocator),
            .before_hooks = std.ArrayList(TransitionHook).init(allocator),
            .after_hooks = std.ArrayList(TransitionHook).init(allocator),
        };
        m.setDefaultTransitions();
        return m;
    }

    pub fn deinit(self: *Machine) void {
        self.transitions.deinit();
        self.before_hooks.deinit();
        self.after_hooks.deinit();
    }

    pub fn current(self: *const Machine) ConnState {
        return self.state;
    }

    pub fn transition(self: *Machine, target: ConnState) !void {
        if (!self.canTransition(self.state, target)) {
            return error.InvalidTransition;
        }

        for (self.before_hooks.items) |hook| {
            try hook(self.state, target);
        }

        const from = self.state;
        self.state = target;

        for (self.after_hooks.items) |hook| {
            try hook(from, target);
        }
    }

    pub fn requireState(self: *const Machine, allowed: []const ConnState) !void {
        for (allowed) |s| {
            if (self.state == s) return;
        }
        return error.InvalidState;
    }

    pub fn onBefore(self: *Machine, hook: TransitionHook) !void {
        try self.before_hooks.append(hook);
    }

    pub fn onAfter(self: *Machine, hook: TransitionHook) !void {
        try self.after_hooks.append(hook);
    }

    pub fn setTransitions(self: *Machine, specs: []const TransitionSpec) void {
        self.transitions.clearAndFree();
        for (specs) |spec| {
            self.transitions.put(spec.from, spec.allowed) catch {};
        }
    }

    pub fn addTransition(self: *Machine, from: ConnState, to: []const ConnState) !void {
        try self.transitions.put(from, to);
    }

    pub fn canTransitionFromCurrent(self: *const Machine, target: ConnState) bool {
        return self.canTransition(self.state, target);
    }

    fn canTransition(self: *const Machine, from: ConnState, to: ConnState) bool {
        if (self.transitions.get(from)) |allowed| {
            for (allowed) |s| {
                if (s == to) return true;
            }
        }
        return false;
    }

    fn setDefaultTransitions(self: *Machine) void {
        const specs = defaultTransitions();
        for (specs) |spec| {
            self.transitions.put(spec.from, spec.allowed) catch {};
        }
    }
};

pub fn defaultTransitions() []const TransitionSpec {
    const S = ConnState;
    return &[_]TransitionSpec{
        .{ .from = S.connect, .allowed = &[_]S{ S.greeted, S.logout } },
        .{ .from = S.greeted, .allowed = &[_]S{ S.ready, S.logout } },
        .{ .from = S.ready, .allowed = &[_]S{ S.mail, S.logout } },
        .{ .from = S.mail, .allowed = &[_]S{ S.rcpt, S.ready, S.logout } },
        .{ .from = S.rcpt, .allowed = &[_]S{ S.rcpt, S.data, S.ready, S.logout } },
        .{ .from = S.data, .allowed = &[_]S{ S.ready, S.logout } },
    };
}

pub fn commandAllowedStates(command: []const u8) []const ConnState {
    const S = ConnState;

    if (eqAny(command, &.{ "EHLO", "HELO" })) {
        return &[_]S{ S.connect, S.greeted, S.ready };
    }
    if (eqAny(command, &.{"STARTTLS"})) {
        return &[_]S{ S.greeted, S.ready };
    }
    if (eqAny(command, &.{"AUTH"})) {
        return &[_]S{ S.greeted, S.ready };
    }
    if (eqAny(command, &.{"MAIL FROM"})) {
        return &[_]S{S.ready};
    }
    if (eqAny(command, &.{"RCPT TO"})) {
        return &[_]S{ S.mail, S.rcpt };
    }
    if (eqAny(command, &.{ "DATA", "BDAT" })) {
        return &[_]S{S.rcpt};
    }
    if (eqAny(command, &.{"RSET"})) {
        return &[_]S{ S.greeted, S.ready, S.mail, S.rcpt };
    }
    if (eqAny(command, &.{"NOOP"})) {
        return &[_]S{ S.greeted, S.ready, S.mail, S.rcpt };
    }
    if (eqAny(command, &.{"QUIT"})) {
        return &[_]S{ S.connect, S.greeted, S.ready, S.mail, S.rcpt, S.data, S.logout };
    }
    if (eqAny(command, &.{ "VRFY", "EXPN", "HELP" })) {
        return &[_]S{ S.greeted, S.ready, S.mail, S.rcpt };
    }

    return &[_]S{};
}

fn eqAny(input: []const u8, candidates: []const []const u8) bool {
    for (candidates) |candidate| {
        if (std.ascii.eqlIgnoreCase(input, candidate)) return true;
    }
    return false;
}
