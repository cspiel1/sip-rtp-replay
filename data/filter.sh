#!/bin/sh
# Filter a pcap file to show only INVITE-transaction SIP messages and the
# RTP audio stream sent by the caller (the host that sent the INVITE).
#
# The caller's audio RTP source port is read from its SDP offer (m=audio line).
# Most SIP endpoints use the same port for sending and receiving (symmetric RTP).
#
# Usage: filter.sh <pcap-file> [output-file]

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pcap-file> [output-file]" >&2
    exit 1
fi

PCAP="$1"

# Source IP of the first INVITE request
CALLER_IP=$(tshark -r "$PCAP" -Y 'sip.Method == "INVITE"' \
    -T fields -e ip.src 2>/dev/null | head -1)

if [ -z "$CALLER_IP" ]; then
    echo "error: no INVITE found in $PCAP" >&2
    exit 1
fi

# Audio RTP port from the caller's SDP offer (m=audio <port> ...)
AUDIO_PORT=$(tshark -r "$PCAP" -Y 'sip.Method == "INVITE"' \
    -T fields -e sdp.media 2>/dev/null | \
    grep -m1 '^audio' | awk '{print $2}')

echo "Caller IP   : $CALLER_IP"
echo "Audio port  : ${AUDIO_PORT:-unknown}"
echo ""

if [ -n "$AUDIO_PORT" ]; then
    RTP_FILTER="rtp and ip.src == $CALLER_IP and udp.srcport == $AUDIO_PORT"
else
    RTP_FILTER="rtp and ip.src == $CALLER_IP"
fi

if [ $# -ge 2 ]; then
    OUTPUT="-w $2"
    echo "Writing filtered packets to $2"
fi

tshark -r "$PCAP" -Y "sip.CSeq.method == \"INVITE\" or ($RTP_FILTER)" $OUTPUT
