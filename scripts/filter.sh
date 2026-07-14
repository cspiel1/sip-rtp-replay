#!/bin/sh
# Filter a pcap file to show INVITE-transaction SIP messages and RTP.
#
# Usage: filter.sh [options] <pcap-file> [output-file]
#
# Options:
#   -h, --help           show this help and exit
#   -l, --list           list RTP streams and exit
#   -s, --ssrc <ssrc>    filter RTP by SSRC (e.g. 0x7FC562C4)

set -e

LIST=0
SSRC=""
PCAP=""
OUTPUT_FILE=""

usage() {
    echo "Usage: $0 [options] <pcap-file> [output-file]"
    echo "  -h, --help           show this help and exit"
    echo "  -l, --list           list RTP streams and exit"
    echo "  -s, --ssrc <ssrc>    filter RTP by SSRC (e.g. 0x7FC562C4)"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)       usage; exit 0 ;;
        -l|--list)       LIST=1; shift ;;
        -s|--ssrc) SSRC="$2"; shift 2 ;;
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
[ -n "$SSRC" ] && RTP_FILTER="$RTP_FILTER and rtp.ssrc == $SSRC"

DISPLAY_FILTER="sip.CSeq.method == \"INVITE\" or ($RTP_FILTER)"

if [ -n "$OUTPUT_FILE" ]; then
    echo "Writing filtered packets to $OUTPUT_FILE"
    tshark -r "$PCAP" -Y "$DISPLAY_FILTER" -w "$OUTPUT_FILE"
else
    tshark -r "$PCAP" -Y "$DISPLAY_FILTER"
fi
