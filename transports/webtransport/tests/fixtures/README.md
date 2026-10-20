# Wire fixtures

Byte captures from real WebTransport implementations, decoded by `tests/fixtures.rs`. The QUIC listener and the native test client both use this codec, so these keep a mistake they share from passing unnoticed. Each file is exactly what the peer put on one QUIC stream, after QUIC decryption and reassembly and before any HTTP/3 parsing.

Captured 2026-10-19 on Linux x86_64 over loopback.

| File | Source | Content |
| --- | --- | --- |
| `chrome_control_stream.bin` | Chrome 155.0.8059.79 (headless) | Client control stream: type `0x00`, SETTINGS, a GREASE frame |
| `chrome_connect_headers.bin` | Chrome 155.0.8059.79 | HEADERS frame of the extended CONNECT |
| `chrome_close_capsule.bin` | Chrome 155.0.8059.79 | DATA frame holding `CLOSE_WEBTRANSPORT_SESSION(7, "bye")` |
| `firefox_control_stream.bin` | Firefox 158.0 (headless) | Client control stream: type `0x00`, SETTINGS, a GREASE frame |
| `firefox_connect_headers.bin` | Firefox 158.0 | HEADERS frame of the extended CONNECT |
| `firefox_close_capsule.bin` | Firefox 158.0 | DATA frame holding `CLOSE_WEBTRANSPORT_SESSION(7, "bye")` |
| `webtransport_go_server_control_stream.bin` | webtransport-go v0.13.0, quic-go v0.62.0 | Server control stream: type `0x00`, SETTINGS |
| `webtransport_go_200_headers.bin` | webtransport-go v0.13.0 | HEADERS frame of the 200 response |

## How

- **Browsers.** A page on `http://127.0.0.1:8409` opened `new WebTransport("https://127.0.0.1:4433/.well-known/libp2p-webtransport?type=noise", { serverCertificateHashes })` against a self-signed ECDSA P-256 certificate, waited for `ready`, then called `close({ closeCode: 7, reason: "bye" })`. The server was aioquic 1.7.0, patched to log every stream's raw bytes before HTTP/3 parsing and to send exactly the SETTINGS minip2p's listener sends, with no QPACK settings: `0x08=1, 0x33=1, 0x2b603742=1, 0x14e9cd29=1, 0x2b61=0x2b64=0x2b65=2^60`. With a QPACK table capacity of 0 both browsers encode CONNECT with Required Insert Count 0, static-table entries and Huffman-coded literals. Firefox ran from the official mozilla.org tarball, because the snap cannot read the capture profile under `/tmp`.
- **webtransport-go.** A Go 1.27.2 server (`http3.Server` with datagrams enabled, `webtransport.ConfigureHTTP3Server`, default `webtransport.Server` config) was dialed by an aioquic H3 client that sent an extended CONNECT to the same path and logged the raw bytes it received.

## Things to know

- GREASE settings and frame types are random per connection, so the values in the browser control streams are particular to these captures.
- Chrome also sends a DATA frame with a GREASE capsule right after its CONNECT HEADERS; it is not part of these files.
- Neither browser sends `WT_MAX_SESSIONS` or the `WT_INITIAL_MAX_*` settings: both use draft-02's `0x2b603742`, so session flow control is never negotiated with them.
- quic-go writes its extra settings from a Go map, so the order of webtransport-go's last settings can differ between runs.
- The `date` value in the 200 response is the capture time.
