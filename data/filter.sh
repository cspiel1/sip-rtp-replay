#!/bin/sh
# Filter a pcap file to show INVITE-transaction SIP messages and RTP.
#
# Usage: filter.sh [options] <pcap-file> [output-file]
#
# Options:
#   -h, --help         show this help and exit
#   -l, --list         list RTP streams (ip.src, ip.dst) and exit
#   -s, --source <ip>  filter RTP by source IP
#   -d, --dest   <ip>  filter RTP by destination IP

set -e

LIST=0
SRC_IP=""
DST_IP=""
PCAP=""
OUTPUT_FILE=""

usage() {
    echo "Usage: $0 [options] <pcap-file> [output-file]"
    echo "  -h, --help         show this help and exit"
    echo "  -l, --list         list RTP streams and exit"
    echo "  -s, --source <ip>  filter RTP by source IP"
    echo "  -d, --dest   <ip>  filter RTP by destination IP"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)         usage; exit 0 ;;
        -l|--list)         LIST=1; shift ;;
        -s|--source) SRC_IP="$2"; shift 2 ;;
        -d|--dest)   DST_IP="$2"; shift 2 ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$PCAP" ]; then
                PCAP="$1"
            elif [ -z "$OUTPUT_FILE" ]; then
                OUTPUT_FILE="$1"
            fi
            shift ;;
    esac
done

if [ -z "$PCAP" ]; then
    usage >&2
    exit 1
fi

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
