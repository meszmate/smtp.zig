pub const builder = @import("builder.zig");
pub const quoted_printable = @import("quoted_printable.zig");
pub const base64 = @import("base64.zig");
pub const headers = @import("headers.zig");

pub const MessageBuilder = builder.MessageBuilder;
pub const encodeQuotedPrintableAlloc = quoted_printable.encodeAlloc;
pub const decodeQuotedPrintableAlloc = quoted_printable.decodeAlloc;
pub const encodeBase64MimeAlloc = base64.encodeMimeAlloc;
pub const encodeHeaderAlloc = headers.encodeWordAlloc;
pub const formatAddressAlloc = headers.formatAddressAlloc;
pub const formatAddressListAlloc = headers.formatAddressListAlloc;
pub const formatMessageIdAlloc = headers.formatMessageIdAlloc;
pub const formatDateAlloc = headers.formatDateAlloc;
