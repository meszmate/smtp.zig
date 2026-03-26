const std = @import("std");
const smtp = @import("smtp");

const Machine = smtp.state.Machine;
const ConnState = smtp.ConnState;

// ---------------------------------------------------------------------------
// Default transitions
// ---------------------------------------------------------------------------

test "state: initial state is what was passed to init" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    try std.testing.expectEqual(ConnState.connect, m.current());
}

test "state: connect -> greeted is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    try m.transition(.greeted);
    try std.testing.expectEqual(ConnState.greeted, m.current());
}

test "state: connect -> logout is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    try m.transition(.logout);
    try std.testing.expectEqual(ConnState.logout, m.current());
}

test "state: greeted -> ready is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .greeted);
    defer m.deinit();
    try m.transition(.ready);
    try std.testing.expectEqual(ConnState.ready, m.current());
}

test "state: ready -> mail is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .ready);
    defer m.deinit();
    try m.transition(.mail);
    try std.testing.expectEqual(ConnState.mail, m.current());
}

test "state: mail -> rcpt is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .mail);
    defer m.deinit();
    try m.transition(.rcpt);
    try std.testing.expectEqual(ConnState.rcpt, m.current());
}

test "state: rcpt -> data is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .rcpt);
    defer m.deinit();
    try m.transition(.data);
    try std.testing.expectEqual(ConnState.data, m.current());
}

test "state: rcpt -> rcpt (multiple recipients) is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .rcpt);
    defer m.deinit();
    try m.transition(.rcpt);
    try std.testing.expectEqual(ConnState.rcpt, m.current());
}

test "state: data -> ready is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .data);
    defer m.deinit();
    try m.transition(.ready);
    try std.testing.expectEqual(ConnState.ready, m.current());
}

test "state: mail -> ready (RSET) is valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .mail);
    defer m.deinit();
    try m.transition(.ready);
    try std.testing.expectEqual(ConnState.ready, m.current());
}

// ---------------------------------------------------------------------------
// Invalid transitions
// ---------------------------------------------------------------------------

test "state: connect -> ready is invalid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    const result = m.transition(.ready);
    try std.testing.expectError(error.InvalidTransition, result);
    try std.testing.expectEqual(ConnState.connect, m.current());
}

test "state: connect -> mail is invalid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    const result = m.transition(.mail);
    try std.testing.expectError(error.InvalidTransition, result);
}

test "state: greeted -> mail is invalid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .greeted);
    defer m.deinit();
    const result = m.transition(.mail);
    try std.testing.expectError(error.InvalidTransition, result);
}

test "state: ready -> data is invalid (need rcpt first)" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .ready);
    defer m.deinit();
    const result = m.transition(.data);
    try std.testing.expectError(error.InvalidTransition, result);
}

test "state: data -> mail is invalid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .data);
    defer m.deinit();
    const result = m.transition(.mail);
    try std.testing.expectError(error.InvalidTransition, result);
}

// ---------------------------------------------------------------------------
// canTransitionFromCurrent
// ---------------------------------------------------------------------------

test "state: canTransitionFromCurrent returns true for valid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    try std.testing.expect(m.canTransitionFromCurrent(.greeted));
    try std.testing.expect(m.canTransitionFromCurrent(.logout));
}

test "state: canTransitionFromCurrent returns false for invalid" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    try std.testing.expect(!m.canTransitionFromCurrent(.ready));
    try std.testing.expect(!m.canTransitionFromCurrent(.data));
}

// ---------------------------------------------------------------------------
// requireState
// ---------------------------------------------------------------------------

test "state: requireState succeeds when state matches" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .ready);
    defer m.deinit();
    try m.requireState(&.{ .ready, .mail });
}

test "state: requireState fails when state does not match" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();
    const result = m.requireState(&.{ .ready, .mail });
    try std.testing.expectError(error.InvalidState, result);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

var hook_log: [2]ConnState = undefined;
var hook_called: bool = false;

fn testBeforeHook(from: ConnState, to: ConnState) anyerror!void {
    hook_log = .{ from, to };
    hook_called = true;
}

test "state: before hook is called on transition" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();

    hook_called = false;
    try m.onBefore(testBeforeHook);
    try m.transition(.greeted);

    try std.testing.expect(hook_called);
    try std.testing.expectEqual(ConnState.connect, hook_log[0]);
    try std.testing.expectEqual(ConnState.greeted, hook_log[1]);
}

var after_hook_called: bool = false;

fn testAfterHook(from: ConnState, to: ConnState) anyerror!void {
    _ = from;
    _ = to;
    after_hook_called = true;
}

test "state: after hook is called on transition" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();

    after_hook_called = false;
    try m.onAfter(testAfterHook);
    try m.transition(.greeted);

    try std.testing.expect(after_hook_called);
}

// ---------------------------------------------------------------------------
// Full session flow
// ---------------------------------------------------------------------------

test "state: full SMTP session flow" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();

    try m.transition(.greeted); // server greeting
    try m.transition(.ready); // EHLO
    try m.transition(.mail); // MAIL FROM
    try m.transition(.rcpt); // RCPT TO
    try m.transition(.rcpt); // RCPT TO (second)
    try m.transition(.data); // DATA
    try m.transition(.ready); // data accepted
    try m.transition(.logout); // QUIT

    try std.testing.expectEqual(ConnState.logout, m.current());
}

// ---------------------------------------------------------------------------
// commandAllowedStates
// ---------------------------------------------------------------------------

test "state: commandAllowedStates for EHLO" {
    const allowed = smtp.state.commandAllowedStates("EHLO");
    try std.testing.expect(allowed.len > 0);
    // EHLO should be allowed in connect, greeted, ready
    var found_connect = false;
    var found_ready = false;
    for (allowed) |s| {
        if (s == .connect) found_connect = true;
        if (s == .ready) found_ready = true;
    }
    try std.testing.expect(found_connect);
    try std.testing.expect(found_ready);
}

test "state: commandAllowedStates for MAIL FROM" {
    const allowed = smtp.state.commandAllowedStates("MAIL FROM");
    try std.testing.expectEqual(@as(usize, 1), allowed.len);
    try std.testing.expectEqual(ConnState.ready, allowed[0]);
}

test "state: commandAllowedStates for RCPT TO" {
    const allowed = smtp.state.commandAllowedStates("RCPT TO");
    try std.testing.expectEqual(@as(usize, 2), allowed.len);
}

test "state: commandAllowedStates for DATA" {
    const allowed = smtp.state.commandAllowedStates("DATA");
    try std.testing.expectEqual(@as(usize, 1), allowed.len);
    try std.testing.expectEqual(ConnState.rcpt, allowed[0]);
}

test "state: commandAllowedStates for QUIT allowed everywhere" {
    const allowed = smtp.state.commandAllowedStates("QUIT");
    // QUIT should be allowed in all states
    try std.testing.expect(allowed.len >= 6);
}

test "state: commandAllowedStates for unknown command returns empty" {
    const allowed = smtp.state.commandAllowedStates("XYZZY");
    try std.testing.expectEqual(@as(usize, 0), allowed.len);
}

// ---------------------------------------------------------------------------
// defaultTransitions
// ---------------------------------------------------------------------------

test "state: defaultTransitions returns non-empty list" {
    const specs = smtp.state.defaultTransitions();
    try std.testing.expect(specs.len > 0);
}

// ---------------------------------------------------------------------------
// addTransition / setTransitions
// ---------------------------------------------------------------------------

test "state: addTransition adds custom transition" {
    const allocator = std.testing.allocator;
    var m = Machine.init(allocator, .connect);
    defer m.deinit();

    // By default connect -> ready is invalid
    try std.testing.expect(!m.canTransitionFromCurrent(.ready));

    // Add custom transition
    try m.addTransition(.connect, &.{ .greeted, .ready, .logout });
    try std.testing.expect(m.canTransitionFromCurrent(.ready));
}
