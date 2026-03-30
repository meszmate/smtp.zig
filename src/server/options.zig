const std = @import("std");
const stream_mod = @import("stream.zig");

const MessageStreamFactory = stream_mod.MessageStreamFactory;

/// TLS upgrade function type. Takes a context and the underlying stream,
/// returns a Transport wrapping the TLS connection.
pub const TlsUpgradeFn = *const fn (ctx: *anyopaque, stream: std.net.Stream) anyerror!void;

/// Configuration options for the SMTP server.
pub const Options = struct {
    /// Greeting text sent in the 220 banner.
    greeting_text: []const u8 = "smtp.zig ESMTP ready",

    /// Server hostname used in EHLO/HELO responses.
    hostname: []const u8 = "localhost",

    /// Maximum message size in bytes (0 = unlimited). Default: 10 MB.
    max_message_size: u64 = 10_485_760,

    /// Maximum number of recipients per message.
    max_recipients: u32 = 100,

    /// Read timeout in milliseconds. 0 means no timeout.
    read_timeout_ms: u64 = 300_000,

    /// Write timeout in milliseconds. 0 means no timeout.
    write_timeout_ms: u64 = 300_000,

    /// Allow authentication over plaintext (non-TLS) connections.
    allow_insecure_auth: bool = false,

    /// Enable the STARTTLS extension.
    enable_starttls: bool = false,

    /// TLS upgrade function called when STARTTLS is negotiated.
    tls_upgrade_fn: ?TlsUpgradeFn = null,

    /// Opaque context passed to the TLS upgrade function.
    tls_upgrade_ctx: ?*anyopaque = null,

    /// Additional capabilities to advertise. If null, defaultCapabilities() is used.
    capabilities: ?[]const []const u8 = null,

    /// Optional streaming delivery hook for DATA/BDAT bodies.
    message_stream_factory: ?MessageStreamFactory = null,

    /// Returns the default set of ESMTP capabilities.
    pub fn defaultCapabilities() []const []const u8 {
        return &default_caps;
    }

    /// Returns capabilities appropriate when STARTTLS is available but not yet active.
    pub fn starttlsCapabilities() []const []const u8 {
        return &starttls_caps;
    }

    /// Returns capabilities with LOGIN disabled (pre-TLS).
    pub fn logindisabledCapabilities() []const []const u8 {
        return &logindisabled_caps;
    }
};

const default_caps = [_][]const u8{
    "PIPELINING",
    "8BITMIME",
    "ENHANCEDSTATUSCODES",
    "CHUNKING",
    "SMTPUTF8",
};

const starttls_caps = [_][]const u8{
    "PIPELINING",
    "8BITMIME",
    "ENHANCEDSTATUSCODES",
    "CHUNKING",
    "SMTPUTF8",
    "STARTTLS",
};

const logindisabled_caps = [_][]const u8{
    "PIPELINING",
    "8BITMIME",
    "ENHANCEDSTATUSCODES",
    "CHUNKING",
    "SMTPUTF8",
    "STARTTLS",
};
