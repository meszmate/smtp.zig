# Contributing to smtp.zig

Thank you for your interest in contributing to smtp.zig! This document provides guidelines and information to help you get started.

## Getting Started

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.15.0 or later, it needs to be compatible with the latest version
- Git

### Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/smtp.zig.git
   cd smtp.zig
   ```

2. Build the project:
   ```bash
   zig build
   ```

3. Run the tests:
   ```bash
   zig build test
   ```

4. Try an example to verify everything works:
   ```bash
   zig build run-simple-client
   ```

## Project Structure

```
smtp.zig/
├── src/
│   ├── root.zig           # Public API exports
│   ├── client/            # SMTP client implementation
│   ├── server/            # SMTP server implementation
│   ├── auth/              # Authentication mechanisms (PLAIN, LOGIN, OAUTHBEARER)
│   ├── dkim/              # DKIM signing (Ed25519-SHA256)
│   ├── mime/              # MIME message parsing and construction
│   ├── queue/             # Message queue with retry strategies
│   ├── store/             # Storage backends (fsstore, pgstore)
│   ├── state/             # SMTP state machine
│   ├── middleware/         # Server middleware
│   ├── extension/         # SMTP extensions
│   ├── wire/              # Wire protocol encoding/decoding
│   ├── address.zig        # Email address validation and MX lookup
│   ├── arc.zig            # ARC (Authenticated Received Chain)
│   ├── dmarc.zig          # DMARC validation
│   ├── dns.zig            # DNS resolution utilities
│   ├── spf.zig            # SPF validation
│   ├── command.zig        # SMTP commands
│   ├── response.zig       # SMTP responses
│   └── types.zig          # Core types
├── tests/                 # Unit tests
├── examples/              # Example applications
└── build.zig              # Build configuration
```

## How to Contribute

### Reporting Bugs

- Open an issue on GitHub with a clear description of the bug
- Include steps to reproduce, expected behavior, and actual behavior
- Mention your OS and Zig version

### Suggesting Features

- Open an issue describing the feature and its use case
- For significant additions, discuss the approach before starting work

### Submitting Changes

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature
   # or
   git checkout -b fix/your-bugfix
   ```

2. Make your changes and ensure:
   - All existing tests pass: `zig build test`
   - New functionality includes tests where applicable
   - Examples still build and run correctly: `zig build`
   - Code compiles without warnings

3. Commit your changes with a clear message:
   ```bash
   git commit -m "Short description of the change"
   ```

4. Push your branch and open a pull request against `main`

## Code Guidelines

### Architecture

smtp.zig is organized around the core SMTP protocol with modular components for each concern:

- **Protocol logic** goes in `src/client/` or `src/server/`
- **Authentication mechanisms** go in `src/auth/` and must be exported in `src/auth/root.zig`
- **Email security modules** (SPF, DKIM, DMARC, ARC) are top-level in `src/`
- **Storage backends** go in `src/store/`

### Style

- Follow the existing code style in the project
- Use the Zig standard library naming conventions (camelCase for functions, snake_case for variables)
- Keep functions focused and reasonably sized
- Use descriptive names over comments where possible

### Testing

- Tests live in the `tests/` directory
- Add tests for new functionality
- Run the full test suite before submitting:
  ```bash
  zig build test
  ```

### Cross-Platform

smtp.zig supports macOS, Linux, and Windows. When making changes:

- Avoid platform-specific code where possible
- Test on your platform and note which platforms you've verified in the PR

## Pull Request Process

1. Ensure CI passes (build + tests run on every PR)
2. Provide a clear description of what the PR does and why
3. Link related issues if applicable
4. Keep PRs focused — one feature or fix per PR

## License

By contributing to smtp.zig, you agree that your contributions will be licensed under the [MIT License](LICENSE).
