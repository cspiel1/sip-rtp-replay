#!/bin/sh
# Print involved SIP stations (UAC/UAS) from a pcap file.
# Shows IP address, From header, Server/User-Agent header, and Request/Status lines.
#
# Usage: sip-stations.sh [options] <pcap-file>
#
# Options:
#   -h, --help  show this help and exit

set -e

usage() {
    echo "Usage: $0 [options] <pcap-file>"
    echo "  -h, --help  show this help and exit"
}

PCAP=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$PCAP" ]; then PCAP="$1"; fi
            shift ;;
    esac
done

if [ -z "$PCAP" ]; then
    usage >&2
    exit 1
fi

tshark -r "$PCAP" -Y sip -T fields \
    -e ip.src \
    -e sip.from.addr \
    -e sip.Server \
    -e sip.User-Agent \
    -e sip.Request-Line \
    -e sip.Status-Line \
    -E separator='|' \
    | awk -F'|' '
{
    ip=$1; from=$2; server=$3; ua=$4; req=$5; status=$6
    label = (server != "" ? server : ua)
    line  = (req    != "" ? req    : status)

    if (!(ip in seen_ip)) {
        ips[++n] = ip
        seen_ip[ip] = 1
    }
    if (from   != "" && ip_from[ip]   == "") ip_from[ip]   = from
    if (label  != "" && ip_label[ip]  == "") ip_label[ip]  = label
    if (line   != "") {
        key = ip SUBSEP line
        if (!(key in seen_line)) {
            seen_line[key] = 1
            ip_lines[ip] = (ip_lines[ip] == "" ? line : ip_lines[ip] "\n           " line)
        }
    }
}
END {
    for (i = 1; i <= n; i++) {
        ip = ips[i]
        printf "IP:      %s\nFrom:    %s\nServer:  %s\nLines:   %s\n\n",
            ip, ip_from[ip], ip_label[ip], ip_lines[ip]
    }
}'
