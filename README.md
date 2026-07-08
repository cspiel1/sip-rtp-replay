# sip-rtp-replay

A SIP/RTP test tool that answers an incoming call and replays a previously
captured RTP audio stream from a pcap file with the original inter-packet
timing.

## Purpose

Useful for testing jitter buffers, audio pipelines, and SIP stacks by
replaying a real-world RTP stream at a controllable target.  The tool acts as
a passive SIP UAS: it accepts any call, sends back the pcap audio, and hangs
up when the stream is exhausted (or immediately when the peer sends BYE).

## Dependencies

| Library | Notes |
|---------|-------|
| [libre](https://github.com/baresip/re) | SIP / SDP / RTP stack |
| [libpcap](https://www.tcpdump.org/) | pcap file reading |

On Arch / Debian the pcap dev package is `libpcap-dev`.
libre must be installed under `/usr/local` (default cmake install prefix).

## Build

```sh
cmake -B build
cmake --build build
```

## Usage

```sh
./build/sip-rtp-replay <pcap-file> [sip-port]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `pcap-file` | — | pcap or pcapng file containing the RTP stream to replay |
| `sip-port` | `5060` | UDP port to listen for incoming SIP INVITE |

### Example

```sh
./build/sip-rtp-replay data/rtp-g722-jitter.pcap
```

Then call `sip:<user>@<host>:5060` from any SIP endpoint.  The tool answers
immediately with a `200 OK` and starts sending RTP.

## Behaviour

1. Loads all RTP packets from the pcap at startup, locking onto the **first
   SSRC** seen (one SSRC = one stream).  If the pcap contains multiple streams
   (both call legs, audio + video) only the first one is used.
2. Listens for an incoming SIP INVITE on UDP.
3. Decodes the SDP offer.  Non-audio media lines (e.g. video) are rejected
   with `m=… 0` in the answer (RFC 3264).
4. Opens a local RTP socket on a random port (10000–20000), replies with
   `200 OK` + SDP answer (`sendonly`).
5. On ACK: sends each RTP packet to the address/port from the SDP answer,
   preserving the original inter-packet timestamps from the pcap.
6. After the last packet: sends BYE after a 100 ms grace period.
7. On BYE from peer: stops replay immediately and cleans up.
8. Returns to idle, ready to accept the next call.

## pcap Filter Script

`data/filter.sh` helps inspect a pcap before use.  It extracts the caller IP
and audio port from the SDP offer and displays only the relevant traffic:

```sh
# Display INVITE-transaction SIP + caller's audio RTP
./data/filter.sh capture.pcap

# Write filtered packets to a new file
./data/filter.sh capture.pcap filtered.pcap
```

### Capturing a suitable pcap with tcpdump

```sh
sudo tcpdump -i eth0 -w capture.pcap 'host <target>'
```

Then inspect with the filter script and pass the result to sip-rtp-replay.

## Supported pcap link types

| DLT | Description |
|-----|-------------|
| `DLT_EN10MB` (1) | Ethernet (with optional 802.1Q VLAN tag) |
| `DLT_LINUX_SLL` (113) | Linux cooked capture (`any` interface) |

## SDP codec support

The SDP answer advertises the following audio codecs.  The negotiated codec
has no effect on replay — the pcap payload is sent as-is with the original
payload type.

| PT | Codec | Clock rate |
|----|-------|-----------|
| 0 | PCMU (G.711 µ-law) | 8000 Hz |
| 8 | PCMA (G.711 A-law) | 8000 Hz |
| 9 | G.722 | 8000 Hz clock (16 kHz sampling) |
| 101 | telephone-event | 8000 Hz |
| 111 | Opus | 48000 Hz |
