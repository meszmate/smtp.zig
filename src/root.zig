pub const types = @import("types.zig");
pub const capability = @import("capability.zig");
pub const command = @import("command.zig");
pub const response = @import("response.zig");
pub const wire = @import("wire/root.zig");
pub const client = @import("client/root.zig");
pub const store = @import("store/root.zig");
pub const server = @import("server/root.zig");
pub const state = @import("state/root.zig");
pub const extension = @import("extension/root.zig");
pub const auth = @import("auth/root.zig");
pub const middleware = @import("middleware/root.zig");
pub const mime = @import("mime/root.zig");
pub const address = @import("address.zig");
pub const dns = @import("dns.zig");
pub const queue = @import("queue/root.zig");
pub const spf = @import("spf.zig");
pub const dmarc = @import("dmarc.zig");
pub const arc = @import("arc.zig");
pub const dkim = @import("dkim/root.zig");

pub const ConnState = types.ConnState;
pub const DsnNotify = types.DsnNotify;
pub const DsnReturn = types.DsnReturn;
pub const BodyType = types.BodyType;
pub const MailOptions = types.MailOptions;
pub const RcptOptions = types.RcptOptions;
pub const SmtpResponse = types.SmtpResponse;
pub const EnhancedCode = types.EnhancedCode;
pub const enhanced_codes = types.enhanced_codes;
pub const Address = types.Address;
pub const Envelope = types.Envelope;
pub const BdatChunk = types.BdatChunk;
pub const SMTPError = types.SMTPError;
pub const TransferEncoding = types.TransferEncoding;
pub const ContentDisposition = types.ContentDisposition;
pub const MimePart = types.MimePart;
pub const MultipartOptions = types.MultipartOptions;
pub const Timeouts = types.Timeouts;
pub const formatDateRfc5322 = types.formatDateRfc5322;

pub const smtptest = @import("smtptest.zig");

pub const Cap = capability.Cap;
pub const caps = capability.caps;
pub const CapabilitySet = capability.CapabilitySet;

pub const commands = command.names;

pub const EmailAddress = address.EmailAddress;
pub const parseEmailAddress = address.parse;
pub const isValidEmail = address.isValid;
pub const normalizeEmail = address.normalizeAlloc;

pub const MxRecord = dns.MxRecord;
pub const lookupMx = dns.lookupMxAlloc;
pub const bestMxHost = dns.bestMxHostAlloc;

pub const response_codes = response.codes;
pub const parseResponseLine = response.parseResponseLine;
pub const parseEnhancedCode = response.parseEnhancedCode;
pub const readResponseAlloc = response.readResponseAlloc;
pub const freeResponse = response.freeResponse;

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
