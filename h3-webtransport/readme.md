# H3 Webtransport

Implementation of Webtransport protocol as extension of the h3 crate

# Status
This crate is still in experimental. The API is subject to change. It may contain bugs and is not yet complete. Use with caution.

## Cinnabar fork APIs

`WebTransportSession` retains the accepted CONNECT stream and its HTTP/3
connection. Drive `maintain()` alongside application stream work; the library
leaves task creation and the connection deadline to its caller.

`recv_session_close()` borrows that session. Dropping the wait retains partial
capsules and trailer state for the next wait. Clean EOF requires completed,
validated trailers. Repeated terminal observations retain the same result and
shared error cause.

`close(code, reason)` sends the close capsule and finishes the CONNECT send
stream. Its result records local DATA and FIN acceptance. Keep the returned
`ClosedWebTransportSession` while driving its `maintain()` method and observing
QUIC retirement under the caller's original deadline. Application streams are
no longer admitted through that returned owner.

Dropping a pending bidirectional or unidirectional opener resets its partially
written stream prefix. Completed openers transfer the original stream to the
caller.

The HTTP/3 server builder's `max_encoded_headers_size` optionally limits encoded
HEADERS before their payload is buffered. Configure the decoded field-section
limit separately. The encoded limit defaults to `None` for existing callers.
