const std = @import("std");

/// Configurable retry policy with exponential backoff.
pub const RetryPolicy = struct {
    max_attempts: u32 = 5,
    initial_delay_ms: u64 = 60_000, // 1 minute
    max_delay_ms: u64 = 3_600_000, // 1 hour
    backoff_multiplier: u32 = 2,

    /// Compute the delay (in milliseconds) before the given attempt number.
    /// Attempt numbers are 1-based (attempt 1 is the first retry).
    pub fn nextRetryDelay(self: RetryPolicy, attempt: u32) u64 {
        if (attempt == 0) return 0;
        var delay = self.initial_delay_ms;
        var i: u32 = 1;
        while (i < attempt) : (i += 1) {
            delay *|= self.backoff_multiplier;
            if (delay >= self.max_delay_ms) {
                return self.max_delay_ms;
            }
        }
        return @min(delay, self.max_delay_ms);
    }

    /// Returns true if another retry should be attempted.
    pub fn shouldRetry(self: RetryPolicy, attempt: u32) bool {
        return attempt < self.max_attempts;
    }
};

/// Exponential backoff helper wrapping a RetryPolicy.
pub const ExponentialBackoff = struct {
    policy: RetryPolicy,

    pub fn init(policy: RetryPolicy) ExponentialBackoff {
        return .{ .policy = policy };
    }

    /// Compute the delay before the given attempt.
    pub fn nextDelay(self: *ExponentialBackoff, attempt: u32) u64 {
        return self.policy.nextRetryDelay(attempt);
    }

    /// Returns true if another retry should be attempted.
    pub fn shouldRetry(self: *const ExponentialBackoff, attempt: u32) bool {
        return self.policy.shouldRetry(attempt);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RetryPolicy nextRetryDelay computes exponential backoff" {
    const policy = RetryPolicy{
        .max_attempts = 5,
        .initial_delay_ms = 1000,
        .max_delay_ms = 16000,
        .backoff_multiplier = 2,
    };

    try std.testing.expectEqual(@as(u64, 0), policy.nextRetryDelay(0));
    try std.testing.expectEqual(@as(u64, 1000), policy.nextRetryDelay(1));
    try std.testing.expectEqual(@as(u64, 2000), policy.nextRetryDelay(2));
    try std.testing.expectEqual(@as(u64, 4000), policy.nextRetryDelay(3));
    try std.testing.expectEqual(@as(u64, 8000), policy.nextRetryDelay(4));
    try std.testing.expectEqual(@as(u64, 16000), policy.nextRetryDelay(5));
}

test "RetryPolicy nextRetryDelay clamps to max" {
    const policy = RetryPolicy{
        .initial_delay_ms = 1000,
        .max_delay_ms = 5000,
        .backoff_multiplier = 2,
    };

    try std.testing.expectEqual(@as(u64, 4000), policy.nextRetryDelay(3));
    try std.testing.expectEqual(@as(u64, 5000), policy.nextRetryDelay(4));
    try std.testing.expectEqual(@as(u64, 5000), policy.nextRetryDelay(10));
}

test "RetryPolicy shouldRetry" {
    const policy = RetryPolicy{ .max_attempts = 3 };

    try std.testing.expect(policy.shouldRetry(0));
    try std.testing.expect(policy.shouldRetry(1));
    try std.testing.expect(policy.shouldRetry(2));
    try std.testing.expect(!policy.shouldRetry(3));
    try std.testing.expect(!policy.shouldRetry(4));
}

test "ExponentialBackoff delegates to policy" {
    var backoff = ExponentialBackoff.init(.{
        .max_attempts = 3,
        .initial_delay_ms = 500,
        .max_delay_ms = 4000,
        .backoff_multiplier = 2,
    });

    try std.testing.expectEqual(@as(u64, 500), backoff.nextDelay(1));
    try std.testing.expectEqual(@as(u64, 1000), backoff.nextDelay(2));
    try std.testing.expect(backoff.shouldRetry(2));
    try std.testing.expect(!backoff.shouldRetry(3));
}

test "RetryPolicy default values" {
    const policy = RetryPolicy{};
    try std.testing.expectEqual(@as(u32, 5), policy.max_attempts);
    try std.testing.expectEqual(@as(u64, 60_000), policy.initial_delay_ms);
    try std.testing.expectEqual(@as(u64, 3_600_000), policy.max_delay_ms);
    try std.testing.expectEqual(@as(u32, 2), policy.backoff_multiplier);
}
