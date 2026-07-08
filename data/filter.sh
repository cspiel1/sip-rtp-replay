#!/bin/sh
# Filter a pcap file to show INVITE-transaction SIP messages and RTP.
#
# Usage: filter.sh [options] <pcap-file> [output-file]
#
# Options:
#   -l, --list         list RTP streams (ip.src, ip.dst) and exit
#   -s, --source <ip>  filter RTP by source IP
#   -d, --dest   <ip>  filter RTP by destination IP

set -e

LIST=0
SRC_IP=""
DST_IP=""

while [ $# -gt 0 ]; do
    case "$1" in
        -l|--list)         LIST=1; shift ;;
        -s|--source) SRC_IP="$2"; shift 2 ;;
        -d|--dest)   DST_IP="$2"; shift 2 ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) break ;;
    esac
done

if [ $# -lt 1 ]; then
    echo "Usage: $0 [options] <pcap-file> [output-file]" >&2
    echo "  -l, --list         list RTP streams and exit" >&2
    echo "  -s, --source <ip>  filter RTP by source IP" >&2
    echo "  -d, --dest   <ip>  filter RTP by destination IP" >&2
    exit 1
fi

PCAP="$1"
OUTPUT_FILE="${2:-}"

if [ "$LIST" = "1" ]; then
    tshark -r "$PCAP" -q -z rtp,streams 2>/dev/null
    exit 0
fi

# Build RTP filter
RTP_FILTER="rtp"
[ -n "$SRC_IP" ] && RTP_FILTER="$RTP_FILTER and ip.src == $SRC_IP"
[ -n "$DST_IP" ] && RTP_FILTER="$RTP_FILTER and ip.dst == $DST_IP"

DISPLAY_FILTER="sip.CSeq.method == \"INVITE\" or ($RTP_FILTER)"

if [ -n "$OUTPUT_FILE" ]; then
    echo "Writing filtered packets to $OUTPUT_FILE"
    tshark -r "$PCAP" -Y "$DISPLAY_FILTER" -w "$OUTPUT_FILE"
else
    tshark -r "$PCAP" -Y "$DISPLAY_FILTER"
fi
