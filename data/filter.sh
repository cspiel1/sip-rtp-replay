#!/bin/sh
# Filter a pcap file to show only INVITE-transaction SIP messages and a
# single RTP audio stream.
#
# By default the stream sent by the CALLER (host that sent the INVITE) is
# selected.  With -r / --reverse the stream sent by the CALLEE (host that
# received the INVITE) is selected instead.
#
# The RTP source port is read from the matching SDP offer/answer m=audio line.
# Most SIP endpoints use the same port for sending and receiving (symmetric RTP).
#
# Usage: filter.sh [-r] <pcap-file> [output-file]

set -e

REVERSE=0
PRINT_ONLY=0

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        -r|--reverse) REVERSE=1; shift ;;
        -p)           PRINT_ONLY=1; shift ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

if [ $# -lt 1 ]; then
    echo "Usage: $0 [-r|--reverse] [-p] <pcap-file> [output-file]" >&2
    echo "  -r, --reverse  filter callee RTP (default: caller)" >&2
    echo "  -p             print tshark command only, do not execute" >&2
    exit 1
fi

PCAP="$1"
OUTPUT_FILE="${2:-}"

# Source IP of the first INVITE request
CALLER_IP=$(tshark -r "$PCAP" -Y 'sip.Method == "INVITE"' \
    -T fields -e ip.src 2>/dev/null | head -1)

if [ -z "$CALLER_IP" ]; then
    echo "error: no INVITE found in $PCAP" >&2
    exit 1
fi

# Destination IP of the INVITE = callee
CALLEE_IP=$(tshark -r "$PCAP" -Y 'sip.Method == "INVITE"' \
    -T fields -e ip.dst 2>/dev/null | head -1)

if [ "$REVERSE" = "1" ]; then
    # Read the callee's RTP source port directly from the captured packets
    AUDIO_PORT=$(tshark -r "$PCAP" -Y "rtp and ip.src == $CALLEE_IP" \
        -T fields -e udp.srcport 2>/dev/null | head -1)
    RTP_IP="$CALLEE_IP"
    ROLE="Callee"
else
    # Caller audio port from the INVITE SDP offer
    AUDIO_PORT=$(tshark -r "$PCAP" -Y 'sip.Method == "INVITE"' \
        -T fields -e sdp.media 2>/dev/null | \
        grep -m1 '^audio' | awk '{print $2}')
    RTP_IP="$CALLER_IP"
    ROLE="Caller"
fi

echo "Caller IP   : $CALLER_IP"
echo "Callee IP   : $CALLEE_IP"
echo "$ROLE RTP  : ${RTP_IP}:${AUDIO_PORT:-?}"
echo ""

if [ -n "$AUDIO_PORT" ]; then
    RTP_FILTER="rtp and ip.src == $RTP_IP and udp.srcport == $AUDIO_PORT"
else
    RTP_FILTER="rtp and ip.src == $RTP_IP"
fi

if [ -n "$OUTPUT_FILE" ]; then
    CMD="tshark -r \"$PCAP\" -Y \"sip.CSeq.method == \\\"INVITE\\\" or ($RTP_FILTER)\" -w \"$OUTPUT_FILE\""
else
    CMD="tshark -r \"$PCAP\" -Y \"sip.CSeq.method == \\\"INVITE\\\" or ($RTP_FILTER)\""
fi

if [ "$PRINT_ONLY" = "1" ]; then
    echo "$CMD"
else
    [ -n "$OUTPUT_FILE" ] && echo "Writing filtered packets to $OUTPUT_FILE"
    eval "$CMD"
fi
