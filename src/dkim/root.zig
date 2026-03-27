pub const canonicalize = @import("canonicalize.zig");
pub const signer = @import("signer.zig");
pub const header = @import("header.zig");
pub const key = @import("key.zig");
pub const dns = @import("dns.zig");

pub const Canonicalization = canonicalize.Canonicalization;
pub const CanonicalizationAlgo = canonicalize.CanonicalizationAlgo;
pub const canonicalizeBody = canonicalize.canonicalizeBody;
pub const canonicalizeHeader = canonicalize.canonicalizeHeader;

pub const Signer = signer.Signer;
pub const SignerOptions = signer.SignerOptions;
pub const Algorithm = signer.Algorithm;
pub const SignResult = signer.SignResult;

pub const DkimHeader = header.DkimHeader;
pub const buildDkimHeaderAlloc = header.buildDkimHeaderAlloc;
pub const parseDkimHeader = header.parseDkimHeader;

pub const Ed25519Key = key.Ed25519Key;
pub const SigningKey = key.SigningKey;
pub const loadEd25519KeyFromPem = key.loadEd25519KeyFromPem;
pub const loadEd25519KeyFromSeed = key.loadEd25519KeyFromSeed;
pub const generateEd25519Key = key.generateEd25519Key;

pub const DnsRecord = dns.DnsRecord;
pub const buildDnsRecordAlloc = dns.buildDnsRecordAlloc;
