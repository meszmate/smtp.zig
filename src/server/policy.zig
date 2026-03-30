const std = @import("std");
const session_mod = @import("session.zig");
const spf = @import("../spf.zig");
const dmarc = @import("../dmarc.zig");

const SessionState = session_mod.SessionState;

pub const Stage = enum {
    command,
    mail_from,
    rcpt_to,
    message,
};

pub const Rejection = struct {
    code: u16,
    message: []const u8,
};

pub const Context = struct {
    allocator: std.mem.Allocator,
    stage: Stage,
    command: []const u8,
    args: []const u8 = "",
    client_id: []const u8 = "",
    timestamp_ms: i64 = 0,
    session: *const SessionState,
    mail_from: ?[]const u8 = null,
    rcpt_to: ?[]const u8 = null,
    message: ?[]const u8 = null,

    pub fn senderDomain(self: Context) []const u8 {
        return extractDomain(self.mail_from orelse "");
    }

    pub fn recipientDomain(self: Context) []const u8 {
        return extractDomain(self.rcpt_to orelse "");
    }
};

pub const Policy = struct {
    context: *anyopaque,
    evaluate_fn: *const fn (ctx: *anyopaque, policy_ctx: *const Context) anyerror!?Rejection,

    pub fn evaluate(self: Policy, policy_ctx: *const Context) !?Rejection {
        return try self.evaluate_fn(self.context, policy_ctx);
    }
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    policies: std.ArrayList(Policy),

    pub fn init(allocator: std.mem.Allocator) Engine {
        return .{
            .allocator = allocator,
            .policies = .empty,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.policies.deinit(self.allocator);
    }

    pub fn use(self: *Engine, policy: Policy) !void {
        try self.policies.append(self.allocator, policy);
    }

    pub fn evaluate(self: *Engine, policy_ctx: *const Context) !?Rejection {
        for (self.policies.items) |policy| {
            if (try policy.evaluate(policy_ctx)) |rejection| {
                return rejection;
            }
        }
        return null;
    }
};

pub const RequireAuthenticationPolicy = struct {
    stages: []const Stage = &.{ .mail_from, .rcpt_to, .message },
    rejection: Rejection = .{
        .code = 530,
        .message = "5.7.0 Authentication required",
    },

    pub fn policy(self: *RequireAuthenticationPolicy) Policy {
        return .{
            .context = @ptrCast(self),
            .evaluate_fn = evaluateFn,
        };
    }

    fn evaluateFn(ctx: *anyopaque, policy_ctx: *const Context) !?Rejection {
        const self: *RequireAuthenticationPolicy = @ptrCast(@alignCast(ctx));
        if (!containsStage(self.stages, policy_ctx.stage)) return null;
        if (policy_ctx.session.authenticated) return null;
        return self.rejection;
    }
};

pub const RelayPolicy = struct {
    local_domains: []const []const u8,
    allow_authenticated_relay: bool = true,
    rejection: Rejection = .{
        .code = 550,
        .message = "5.7.1 Relay denied",
    },

    pub fn policy(self: *RelayPolicy) Policy {
        return .{
            .context = @ptrCast(self),
            .evaluate_fn = evaluateFn,
        };
    }

    fn evaluateFn(ctx: *anyopaque, policy_ctx: *const Context) !?Rejection {
        const self: *RelayPolicy = @ptrCast(@alignCast(ctx));
        if (policy_ctx.stage != .rcpt_to) return null;

        const domain = policy_ctx.recipientDomain();
        if (domain.len == 0) return null;
        if (isLocalDomain(self.local_domains, domain)) return null;
        if (self.allow_authenticated_relay and policy_ctx.session.authenticated) return null;
        return self.rejection;
    }
};

pub const RecipientValidationPolicy = struct {
    context: *anyopaque,
    validate_fn: *const fn (ctx: *anyopaque, recipient: []const u8, policy_ctx: *const Context) anyerror!?Rejection,

    pub fn policy(self: *RecipientValidationPolicy) Policy {
        return .{
            .context = @ptrCast(self),
            .evaluate_fn = evaluateFn,
        };
    }

    fn evaluateFn(ctx: *anyopaque, policy_ctx: *const Context) !?Rejection {
        const self: *RecipientValidationPolicy = @ptrCast(@alignCast(ctx));
        if (policy_ctx.stage != .rcpt_to) return null;
        const recipient = policy_ctx.rcpt_to orelse return null;
        return try self.validate_fn(self.context, recipient, policy_ctx);
    }
};

pub const RateLimitPolicy = struct {
    allocator: std.mem.Allocator,
    max_commands: u32,
    window_ms: u64,
    clients: std.StringHashMap(WindowState),
    rejection: Rejection = .{
        .code = 421,
        .message = "4.7.0 Rate limit exceeded",
    },

    const WindowState = struct {
        count: u32,
        window_start_ms: i64,
    };

    pub fn init(allocator: std.mem.Allocator, max_commands: u32, window_ms: u64) RateLimitPolicy {
        return .{
            .allocator = allocator,
            .max_commands = max_commands,
            .window_ms = window_ms,
            .clients = std.StringHashMap(WindowState).init(allocator),
        };
    }

    pub fn deinit(self: *RateLimitPolicy) void {
        var it = self.clients.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.clients.deinit();
    }

    pub fn policy(self: *RateLimitPolicy) Policy {
        return .{
            .context = @ptrCast(self),
            .evaluate_fn = evaluateFn,
        };
    }

    fn evaluateFn(ctx: *anyopaque, policy_ctx: *const Context) !?Rejection {
        const self: *RateLimitPolicy = @ptrCast(@alignCast(ctx));
        if (policy_ctx.stage != .command) return null;

        const client_id = if (policy_ctx.client_id.len > 0) policy_ctx.client_id else "anonymous";
        const entry = try self.clients.getOrPut(client_id);
        if (!entry.found_existing) {
            entry.key_ptr.* = try self.allocator.dupe(u8, client_id);
            entry.value_ptr.* = .{
                .count = 0,
                .window_start_ms = policy_ctx.timestamp_ms,
            };
        }

        const window_limit: i64 = @intCast(self.window_ms);
        if (policy_ctx.timestamp_ms - entry.value_ptr.window_start_ms >= window_limit) {
            entry.value_ptr.* = .{
                .count = 0,
                .window_start_ms = policy_ctx.timestamp_ms,
            };
        }

        entry.value_ptr.count += 1;
        if (entry.value_ptr.count > self.max_commands) {
            return self.rejection;
        }
        return null;
    }
};

pub const MailAuthAssessment = struct {
    spf_result: ?spf.SpfResult = null,
    spf_domain: ?[]const u8 = null,
    dkim_pass: bool = false,
    dkim_domain: ?[]const u8 = null,
    dmarc_record: ?dmarc.DmarcRecord = null,
};

pub const MailAuthPolicy = struct {
    context: *anyopaque,
    assess_fn: *const fn (ctx: *anyopaque, policy_ctx: *const Context) anyerror!MailAuthAssessment,
    reject_on_spf_fail: bool = false,
    reject_on_dmarc_fail: bool = true,
    spf_rejection: Rejection = .{
        .code = 550,
        .message = "5.7.1 SPF validation failed",
    },
    dmarc_rejection: Rejection = .{
        .code = 550,
        .message = "5.7.1 DMARC validation failed",
    },

    pub fn policy(self: *MailAuthPolicy) Policy {
        return .{
            .context = @ptrCast(self),
            .evaluate_fn = evaluateFn,
        };
    }

    fn evaluateFn(ctx: *anyopaque, policy_ctx: *const Context) !?Rejection {
        const self: *MailAuthPolicy = @ptrCast(@alignCast(ctx));
        if (policy_ctx.stage != .message) return null;

        const assessment = try self.assess_fn(self.context, policy_ctx);
        if (self.reject_on_spf_fail and assessment.spf_result == .fail) {
            return self.spf_rejection;
        }

        if (!self.reject_on_dmarc_fail) return null;
        const record = assessment.dmarc_record orelse return null;
        const from_domain = policy_ctx.senderDomain();
        if (from_domain.len == 0) return null;

        const eval = dmarc.evaluate(
            record,
            from_domain,
            assessment.spf_domain,
            assessment.spf_result != null and assessment.spf_result.?.isPass(),
            assessment.dkim_domain,
            assessment.dkim_pass,
        );
        if (eval.result == .fail) {
            return self.dmarc_rejection;
        }

        return null;
    }
};

fn containsStage(stages: []const Stage, target: Stage) bool {
    for (stages) |stage| {
        if (stage == target) return true;
    }
    return false;
}

fn isLocalDomain(domains: []const []const u8, domain: []const u8) bool {
    for (domains) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, domain)) return true;
    }
    return false;
}

fn extractDomain(address: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, address, " <>\t");
    if (std.mem.indexOfScalar(u8, trimmed, '@')) |idx| {
        return trimmed[idx + 1 ..];
    }
    return "";
}
