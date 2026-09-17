# R03 Messenger Wire Formats

All R03 messenger codecs are private and receive explicit `Limits`. No decoder
allocates a declared segment, address or authentication payload before checking
its configured bound.

## Banner And Frames

The v2 banner is `ceph v2\n` followed by revision-1 supported and required
feature masks as little-endian `u64` values. Negotiation rejects unsupported
required features.

A CRC frame has a 32-byte preamble containing the tag and up to four segment
descriptors, followed by the preamble CRC32C, aligned segment data and a late
epilogue. Segment alignments are 8 bytes except message data, which uses 4096.
The late status is complete or aborted; enabled data CRCs cover segment data.
Truncation, invalid tags/counts/alignments/status, size overflow and CRC
mismatch fail before returning a frame.

A message uses tag 17 and one to four segments. Segment zero is the exact
41-byte little-endian header. Front, middle and data segment lengths must equal
the header-adjacent length fields, `data_pre_padding_length` cannot exceed data,
and absent trailing segments decode as empty. Control tags 1 through 20 use one
8-byte-aligned segment; compression tags are recognized but their payloads are
unsupported in R03.

## Secure Mode

Secure records use AES-128-GCM with the first 16 secret bytes as the key and
crossed client transmit/receive nonce seeds from a 64-byte synthetic secret.
Each direction owns a monotonic `u64` counter and refuses reuse after exhaustion.
The first record seals the preamble plus 48 inline bytes; additional padded
records carry the remainder and later segments. Every record has a 16-byte GCM
tag.

Decoding authenticates before exposing plaintext, validates zero padding and
late completion status, and consumes the nonce even when authentication fails.
Corrupted ciphertext, tags, padding or status never reaches control/message
dispatch. These constructions are validated with synthetic secrets and P02
vectors only; R04 owns negotiated secrets and live authenticated mode.
