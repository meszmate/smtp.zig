const std = @import("std");

/// Represents an SMTP extension with its metadata.
pub const Extension = struct {
    /// Extension name (e.g., "8BITMIME", "PIPELINING").
    name: []const u8,

    /// EHLO keyword to advertise. May include parameters.
    ehlo_keyword: []const u8,

    /// Human-readable description.
    description: []const u8 = "",

    /// RFC reference.
    rfc: []const u8 = "",

    /// Whether this extension is enabled by default.
    default_enabled: bool = true,

    /// Dependencies on other extensions (by name).
    dependencies: []const []const u8 = &.{},
};
