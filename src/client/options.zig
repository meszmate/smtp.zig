const std = @import("std");
const tls_transport = @import("../wire/tls_transport.zig");

pub const TlsOptions = tls_transport.TlsOptions;

/// Configuration options for the SMTP client.
pub const Options = struct {
    /// Read timeout in milliseconds. 0 means no timeout.
    read_timeout_ms: u32 = 30_000,

    /// Write timeout in milliseconds. 0 means no timeout.
    write_timeout_ms: u32 = 30_000,

    /// Maximum SMTP response line length accepted from the server.
    max_response_line_length: usize = 8 * 1024,

    /// When true, logs all SMTP commands and responses to stderr.
    debug_log: bool = false,

    /// TLS configuration for STARTTLS or implicit TLS connections.
    tls_options: ?TlsOptions = null,
};
