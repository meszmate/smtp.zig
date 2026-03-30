# smtp.zig

A comprehensive SMTP library for Zig, providing client, server, and email security features.

## Features

- **SMTP Client** — Connect, authenticate, and send emails with TLS support
- **SMTP Server** — Configurable server with middleware and extension support
- **Authentication** — PLAIN, LOGIN, and OAUTHBEARER mechanisms
- **DKIM** — Ed25519-SHA256 signing with header canonicalization
- **SPF** — Sender Policy Framework validation
- **DMARC** — Domain-based Message Authentication, Reporting & Conformance
- **ARC** — Authenticated Received Chain signing and validation
- **MIME** — Message parsing and construction
- **Message Queue** — Persistent queue with configurable retry strategies
- **Storage Backends** — Filesystem and PostgreSQL store implementations
- **Email Validation** — RFC-compliant address parsing and MX lookup
- **State Machine** — Protocol state management for client and server
- **Middleware** — Extensible server middleware pipeline
- **Cross-platform** — Works on macOS, Linux, and Windows

## Installation

Add smtp.zig to your `build.zig.zon`:

```zig
.dependencies = .{
    .smtp = .{
        .url = "https://github.com/meszmate/smtp.zig/archive/refs/heads/main.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const smtp = b.dependency("smtp", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("smtp", smtp.module("smtp"));
```

## Quick Start

### Sending an Email

```zig
const std = @import("std");
const smtp = @import("smtp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = try smtp.client.Client.connectTcp(allocator, "smtp.example.com", 587);
    defer client.deinit();

    _ = try client.ehlo("localhost");
    if (client.supportsStartTLS()) {
        _ = try client.starttls(.{
            .host_verification = .{ .explicit = "smtp.example.com" },
        });
    }
    try client.authenticatePlain("user@example.com", "password");
    _ = try client.sendMail(
        "sender@example.com",
        &.{"recipient@example.com"},
        "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\n\r\nHello, World!\r\n",
    );
    _ = try client.quit();
}
```

### Email Validation

```zig
const smtp = @import("smtp");

// Validate an email address
const valid = smtp.isValidEmail("user@example.com");

// Parse with full details
const addr = try smtp.parseEmailAddress("User Name <user@example.com>");
```

### MX Lookup

```zig
const smtp = @import("smtp");

// Find the best MX host for a domain
const mx_host = try smtp.bestMxHost(allocator, "example.com");
defer allocator.free(mx_host);
```

## Modules

| Module | Description |
|--------|-------------|
| `client` | SMTP client with TLS, authentication, and pipelining |
| `server` | SMTP server with middleware and extensions |
| `auth` | Authentication mechanisms (PLAIN, LOGIN, OAUTHBEARER) |
| `dkim` | DKIM signing with Ed25519-SHA256 |
| `spf` | SPF record parsing and validation |
| `dmarc` | DMARC policy evaluation |
| `arc` | ARC chain validation and signing |
| `mime` | MIME message parsing and construction |
| `queue` | Message queue with retry strategies |
| `store` | Storage backends (filesystem, PostgreSQL) |
| `address` | Email address validation and normalization |
| `dns` | DNS resolution utilities (MX, TXT) |
| `wire` | Wire protocol encoding/decoding |
| `state` | SMTP state machine |
| `middleware` | Server middleware pipeline |
| `extension` | SMTP extension handling |

## Examples

Build and run examples:

```bash
zig build run-simple_client
zig build run-simple_server
zig build run-proxy
```

## Testing

```bash
zig build test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
