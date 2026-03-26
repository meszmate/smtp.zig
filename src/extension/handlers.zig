const std = @import("std");
const extension_mod = @import("extension.zig");

const Extension = extension_mod.Extension;

/// Built-in SMTP extension definitions.
pub const Builtins = struct {
    pub const @"8bitmime" = Extension{
        .name = "8BITMIME",
        .ehlo_keyword = "8BITMIME",
        .description = "8-bit MIME transport",
        .rfc = "RFC 6152",
    };

    pub const pipelining = Extension{
        .name = "PIPELINING",
        .ehlo_keyword = "PIPELINING",
        .description = "Command pipelining",
        .rfc = "RFC 2920",
    };

    pub const chunking = Extension{
        .name = "CHUNKING",
        .ehlo_keyword = "CHUNKING",
        .description = "BDAT chunking",
        .rfc = "RFC 3030",
    };

    pub const dsn = Extension{
        .name = "DSN",
        .ehlo_keyword = "DSN",
        .description = "Delivery Status Notifications",
        .rfc = "RFC 3461",
    };

    pub const enhancedstatuscodes = Extension{
        .name = "ENHANCEDSTATUSCODES",
        .ehlo_keyword = "ENHANCEDSTATUSCODES",
        .description = "Enhanced status codes",
        .rfc = "RFC 2034",
    };

    pub const smtputf8 = Extension{
        .name = "SMTPUTF8",
        .ehlo_keyword = "SMTPUTF8",
        .description = "Internationalized email",
        .rfc = "RFC 6531",
    };

    pub const size = Extension{
        .name = "SIZE",
        .ehlo_keyword = "SIZE",
        .description = "Message size declaration",
        .rfc = "RFC 1870",
    };

    pub const starttls = Extension{
        .name = "STARTTLS",
        .ehlo_keyword = "STARTTLS",
        .description = "TLS via STARTTLS",
        .rfc = "RFC 3207",
    };

    pub const auth = Extension{
        .name = "AUTH",
        .ehlo_keyword = "AUTH",
        .description = "SMTP Authentication",
        .rfc = "RFC 4954",
    };

    pub const vrfy = Extension{
        .name = "VRFY",
        .ehlo_keyword = "VRFY",
        .description = "Verify user",
        .rfc = "RFC 5321",
        .default_enabled = false,
    };

    pub const help = Extension{
        .name = "HELP",
        .ehlo_keyword = "HELP",
        .description = "Help information",
        .rfc = "RFC 5321",
        .default_enabled = false,
    };

    pub const requiretls = Extension{
        .name = "REQUIRETLS",
        .ehlo_keyword = "REQUIRETLS",
        .description = "Require TLS for delivery",
        .rfc = "RFC 8689",
        .default_enabled = false,
        .dependencies = &.{"STARTTLS"},
    };

    pub const deliverby = Extension{
        .name = "DELIVERBY",
        .ehlo_keyword = "DELIVERBY",
        .description = "Deliver by time",
        .rfc = "RFC 2852",
        .default_enabled = false,
    };

    pub const etrn = Extension{
        .name = "ETRN",
        .ehlo_keyword = "ETRN",
        .description = "Remote message queue starting",
        .rfc = "RFC 1985",
        .default_enabled = false,
    };

    /// Returns all built-in extensions.
    pub fn all() []const Extension {
        return &all_extensions;
    }

    /// Returns only the default-enabled extensions.
    pub fn defaults() []const Extension {
        return &default_extensions;
    }
};

const all_extensions = [_]Extension{
    Builtins.@"8bitmime",
    Builtins.pipelining,
    Builtins.chunking,
    Builtins.dsn,
    Builtins.enhancedstatuscodes,
    Builtins.smtputf8,
    Builtins.size,
    Builtins.starttls,
    Builtins.auth,
    Builtins.vrfy,
    Builtins.help,
    Builtins.requiretls,
    Builtins.deliverby,
    Builtins.etrn,
};

const default_extensions = [_]Extension{
    Builtins.@"8bitmime",
    Builtins.pipelining,
    Builtins.chunking,
    Builtins.enhancedstatuscodes,
    Builtins.smtputf8,
    Builtins.size,
};
