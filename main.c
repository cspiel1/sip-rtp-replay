/**
 * sip-rtp-replay -- answer an incoming SIP call and replay an RTP stream
 *                   from a pcap file with the original inter-packet timing.
 *
 * Usage:  sip-rtp-replay <pcap-file>  [sip-port]
 *
 * The program:
 *   - listens for an incoming SIP INVITE
 *   - immediately answers with 200 OK + SDP (sendonly)
 *   - ignores incoming RTP
 *   - replays every RTP packet from the pcap to the address/port
 *     negotiated in the SDP answer, preserving the original timing
 */

#include <re/re.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* Linux Cooked Capture v1 header length */
#define LINUX_SLL_LEN  16

/* -------------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------- */

/** One captured RTP packet */
struct rtp_pkt {
	struct le      le;
	uint64_t       ts_us;       /**< pcap capture time [microseconds]  */
	struct rtp_header hdr;      /**< decoded RTP header                 */
	uint8_t       *payload;     /**< RTP payload bytes                  */
	size_t         payload_len;
};

/** Application state */
struct app {
	struct sip          *sip;
	struct sipsess_sock *ssock;
	struct sipsess      *sess;
	struct sdp_session  *sdp;
	struct sdp_media    *audio;
	struct rtp_sock     *rtp;
	struct tmr           tmr;

	struct list          pktl;   /**< list<rtp_pkt> loaded from pcap    */
	struct le           *cur;    /**< next packet to send               */

	struct sa            rtp_dst;/**< remote RTP destination from SDP   */
	bool                 active; /**< call is established                */
};

static struct app g_app;

/* -------------------------------------------------------------------------
 * pcap loading
 * ---------------------------------------------------------------------- */

static void rtp_pkt_destructor(void *data)
{
	struct rtp_pkt *p = data;
	list_unlink(&p->le);
	mem_deref(p->payload);
}

/**
 * Load all RTP packets from a pcap file into app->pktl.
 *
 * Supports link types:
 *   DLT_EN10MB (1)   – Ethernet
 *   DLT_LINUX_SLL (113) – Linux cooked capture
 *
 * Only packets belonging to the first RTP SSRC encountered are kept.
 * This correctly handles captures that contain multiple streams
 * (e.g. both call legs, or audio + video).
 */
static int load_pcap(struct app *app, const char *path)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pc;
	struct pcap_pkthdr *ph;
	const uint8_t *data;
	int dlt, rc;
	unsigned count = 0;
	uint32_t ssrc_filter = 0;
	bool ssrc_set = false;

	pc = pcap_open_offline(path, errbuf);
	if (!pc) {
		(void)re_fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
		return EINVAL;
	}

	dlt = pcap_datalink(pc);

	while ((rc = pcap_next_ex(pc, &ph, &data)) == 1) {
		const uint8_t *p = data;
		uint32_t remaining = ph->caplen;
		size_t l2_hlen;

		/* --- L2 header -------------------------------------------- */
		if (dlt == DLT_EN10MB) {
			if (remaining < ETHER_HDR_LEN)
				continue;
			/* check EtherType: skip 802.1Q vlan tag if present */
			const struct ether_header *eh =
				(const struct ether_header *)p;
			l2_hlen = ETHER_HDR_LEN;
			if (ntohs(eh->ether_type) == 0x8100) {
				/* 4-byte 802.1Q tag */
				l2_hlen += 4;
			}
		} else if (dlt == DLT_LINUX_SLL) {
			l2_hlen = LINUX_SLL_LEN;
		} else {
			(void)re_fprintf(stderr,
				"load_pcap: unsupported link type %d\n", dlt);
			pcap_close(pc);
			return ENOTSUP;
		}

		if (remaining < l2_hlen)
			continue;
		p         += l2_hlen;
		remaining -= (uint32_t)l2_hlen;

		/* --- IP header -------------------------------------------- */
		if (remaining < sizeof(struct ip))
			continue;
		const struct ip *iph = (const struct ip *)p;
		if (iph->ip_p != IPPROTO_UDP)
			continue;
		size_t ip_hlen = (size_t)iph->ip_hl * 4;
		if (remaining < ip_hlen)
			continue;
		p         += ip_hlen;
		remaining -= (uint32_t)ip_hlen;

		/* --- UDP header ------------------------------------------- */
		if (remaining < sizeof(struct udphdr))
			continue;
		p         += sizeof(struct udphdr);
		remaining -= sizeof(struct udphdr);

		/* --- RTP header ------------------------------------------- */
		if (remaining < RTP_HEADER_SIZE)
			continue;

		/* Use an mbuf to decode the RTP header */
		struct mbuf mb;
		mbuf_init(&mb);
		mb.buf  = (uint8_t *)(uintptr_t)p; /* const-cast, read-only */
		mb.size = remaining;
		mb.pos  = 0;
		mb.end  = remaining;

		struct rtp_header hdr;
		if (rtp_hdr_decode(&hdr, &mb) != 0)
			continue;

		/* Lock onto the first SSRC seen; drop all others */
		if (!ssrc_set) {
			ssrc_filter = hdr.ssrc;
			ssrc_set    = true;
			(void)re_printf("load_pcap: selected SSRC 0x%08x"
					" (PT %u)\n", ssrc_filter, hdr.pt);
		} else if (hdr.ssrc != ssrc_filter) {
			continue;
		}

		size_t payload_len = mbuf_get_left(&mb);

		struct rtp_pkt *pkt = mem_zalloc(sizeof(*pkt),
						 rtp_pkt_destructor);
		if (!pkt) {
			pcap_close(pc);
			return ENOMEM;
		}

		pkt->ts_us      = (uint64_t)ph->ts.tv_sec * 1000000ULL
				  + (uint64_t)ph->ts.tv_usec;
		pkt->hdr        = hdr;
		pkt->payload_len = payload_len;

		if (payload_len > 0) {
			pkt->payload = mem_alloc(payload_len, NULL);
			if (!pkt->payload) {
				mem_deref(pkt);
				pcap_close(pc);
				return ENOMEM;
			}
			memcpy(pkt->payload, mbuf_buf(&mb), payload_len);
		}

		list_append(&app->pktl, &pkt->le, pkt);
		++count;
	}

	pcap_close(pc);

	if (count == 0) {
		(void)re_fprintf(stderr,
			"load_pcap: no RTP packets found in %s\n", path);
		return ENOENT;
	}

	(void)re_printf("load_pcap: loaded %u RTP packets from %s\n",
			count, path);
	return 0;
}

/* -------------------------------------------------------------------------
 * RTP replay
 * ---------------------------------------------------------------------- */

static void send_next_packet(void *arg);

static void send_bye(void *arg)
{
	struct app *app = arg;
	(void)re_printf("replay: done – sending BYE\n");
	app->sess = mem_deref(app->sess);
}

static void schedule_next(struct app *app)
{
	struct le *next = app->cur->next;
	if (!next) {
		(void)re_printf("replay: all %u packets sent\n",
				list_count(&app->pktl));
		tmr_start(&app->tmr, 100, send_bye, app);
		return;
	}

	const struct rtp_pkt *p0 = list_ledata(app->cur);
	const struct rtp_pkt *p1 = list_ledata(next);

	app->cur = next;

	uint64_t delta_us = (p1->ts_us >= p0->ts_us)
			    ? (p1->ts_us - p0->ts_us) : 0;
	uint64_t delay_ms = delta_us / 1000;
	if (delay_ms == 0)
		delay_ms = 1;

	tmr_start(&app->tmr, delay_ms, send_next_packet, app);
}

static void send_next_packet(void *arg)
{
	struct app *app = arg;

	if (!app->active || !app->cur)
		return;

	const struct rtp_pkt *pkt = list_ledata(app->cur);

	struct mbuf *mb = mbuf_alloc(RTP_HEADER_SIZE + pkt->payload_len);
	if (!mb)
		goto next;

	/* leave headroom for the RTP header that rtp_send prepends */
	mb->pos = RTP_HEADER_SIZE;
	mb->end = RTP_HEADER_SIZE;
	if (pkt->payload_len > 0)
		(void)mbuf_write_mem(mb, pkt->payload, pkt->payload_len);
	mb->pos = RTP_HEADER_SIZE;

	int err = rtp_send(app->rtp, &app->rtp_dst,
			   pkt->hdr.ext, pkt->hdr.m,
			   pkt->hdr.pt, pkt->hdr.ts,
			   0, mb);
	if (err)
		(void)re_fprintf(stderr, "rtp_send: %m\n", err);

	mem_deref(mb);

next:
	schedule_next(app);
}

static void start_rtp_replay(struct app *app)
{
	app->cur = list_head(&app->pktl);
	if (!app->cur) {
		(void)re_fprintf(stderr, "replay: packet list is empty\n");
		return;
	}

	app->active = true;
	(void)re_printf("replay: starting → %J\n", &app->rtp_dst);
	send_next_packet(app);
}

/* -------------------------------------------------------------------------
 * SIP session callbacks
 * ---------------------------------------------------------------------- */

static void rtp_recv_handler(const struct sa *src,
			     const struct rtp_header *hdr,
			     struct mbuf *mb, void *arg)
{
	(void)src; (void)hdr; (void)mb; (void)arg;
	/* intentionally ignored */
}

static void estab_handler(const struct sip_msg *msg, void *arg)
{
	struct app *app = arg;
	(void)msg;

	const struct sa *raddr = sdp_media_raddr(app->audio);
	if (!raddr) {
		(void)re_fprintf(stderr, "estab: no remote RTP address\n");
		return;
	}
	sa_cpy(&app->rtp_dst, raddr);

	(void)re_printf("call established – remote RTP: %J\n", &app->rtp_dst);
	start_rtp_replay(app);
}

static int offer_handler(struct mbuf **descp,
			 const struct sip_msg *msg, void *arg)
{
	/* re-INVITE: just re-encode the current SDP as answer */
	struct app *app = arg;
	(void)msg;
	return sdp_encode(descp, app->sdp, false);
}

static int answer_handler(const struct sip_msg *msg, void *arg)
{
	(void)msg; (void)arg;
	return 0;
}

static void close_handler(int err, const struct sip_msg *msg, void *arg)
{
	struct app *app = arg;
	(void)msg;

	(void)re_printf("call closed (%m)\n", err);
	app->active = false;
	app->cur    = NULL;
	tmr_cancel(&app->tmr);
	app->sess = mem_deref(app->sess);
	app->rtp  = mem_deref(app->rtp);
	(void)re_printf("ready – waiting for next call\n");
}

/**
 * Incoming INVITE handler (sipsess connection callback).
 *
 * Decodes the SDP offer, opens an RTP socket, encodes the SDP answer,
 * and immediately accepts with 200 OK.
 */
static void conn_handler(const struct sip_msg *msg, void *arg)
{
	struct app *app = arg;
	struct mbuf *desc = NULL;
	int err;

	(void)re_printf("incoming INVITE from %r\n", &msg->from.auri);

	if (app->sess) {
		/* already in a call – reject */
		(void)sip_reply(app->sip, msg, 486, "Busy Here");
		return;
	}

	/* Use our SIP destination address as the local media address */
	struct sa lmedia;
	sa_cpy(&lmedia, &msg->dst);
	sa_set_port(&lmedia, 0);
	sdp_session_set_laddr(app->sdp, &lmedia);

	/* Decode SDP offer from the INVITE body */
	if (mbuf_get_left(msg->mb) == 0) {
		(void)re_fprintf(stderr, "conn: INVITE has no SDP body\n");
		(void)sip_reply(app->sip, msg, 488, "Not Acceptable Here");
		return;
	}

	/* sdp_decode advances msg->mb->pos – work on a copy */
	struct mbuf *offer = mbuf_alloc(mbuf_get_left(msg->mb));
	if (!offer)
		return;
	(void)mbuf_write_mem(offer, mbuf_buf(msg->mb),
			     mbuf_get_left(msg->mb));
	offer->pos = 0;

	err = sdp_decode(app->sdp, offer, true);
	mem_deref(offer);
	if (err) {
		(void)re_fprintf(stderr, "conn: sdp_decode failed: %m\n", err);
		(void)sip_reply(app->sip, msg, 488, "Not Acceptable Here");
		return;
	}

	/* Open local RTP socket */
	err = rtp_listen(&app->rtp, IPPROTO_UDP, &lmedia,
			 10000, 20000, false,
			 rtp_recv_handler, NULL, app);
	if (err) {
		(void)re_fprintf(stderr, "conn: rtp_listen failed: %m\n", err);
		(void)sip_reply(app->sip, msg, 500, "Server Error");
		return;
	}

	/* Advertise our RTP port in the SDP answer */
	uint16_t lport = sa_port(rtp_local(app->rtp));
	sdp_media_set_lport(app->audio, lport);
	sdp_media_set_ldir(app->audio, SDP_SENDONLY);

	/* Encode SDP answer */
	err = sdp_encode(&desc, app->sdp, false);
	if (err) {
		(void)re_fprintf(stderr, "conn: sdp_encode failed: %m\n", err);
		(void)sip_reply(app->sip, msg, 500, "Server Error");
		app->rtp = mem_deref(app->rtp);
		return;
	}

	(void)re_printf("local RTP port: %u\n", lport);

	/* Accept the call – send 200 OK with SDP answer */
	err = sipsess_accept(&app->sess, app->ssock, msg,
			     200, "OK",
			     REL100_DISABLED,
			     "sip-rtp-replay",
			     "application/sdp",
			     desc,
			     NULL, NULL, false,
			     offer_handler,
			     answer_handler,
			     estab_handler,
			     NULL, NULL,
			     close_handler,
			     app,
			     NULL);
	mem_deref(desc);

	if (err)
		(void)re_fprintf(stderr,
			"conn: sipsess_accept failed: %m\n", err);
}

/* -------------------------------------------------------------------------
 * Signal handler & main
 * ---------------------------------------------------------------------- */

static void signal_handler(int sig)
{
	(void)sig;
	re_cancel();
}

static void app_destroy(struct app *app)
{
	tmr_cancel(&app->tmr);
	app->sess  = mem_deref(app->sess);
	app->rtp   = mem_deref(app->rtp);
	app->ssock = mem_deref(app->ssock);
	/* app->audio is owned by app->sdp – freed with the session */
	app->audio = NULL;
	app->sdp   = mem_deref(app->sdp);
	sip_close(app->sip, true);
	app->sip   = mem_deref(app->sip);

	/* free packet list */
	struct le *le;
	while ((le = list_head(&app->pktl)) != NULL)
		mem_deref(list_ledata(le));
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		(void)re_fprintf(stderr,
			"Usage: %s <pcap-file> [sip-port]\n", argv[0]);
		return 1;
	}

	const char *pcap_path = argv[1];
	uint16_t sip_port = (argc >= 3) ? (uint16_t)atoi(argv[2]) : 5060;

	int err = libre_init();
	if (err) {
		(void)re_fprintf(stderr, "libre_init: %m\n", err);
		return 1;
	}

	memset(&g_app, 0, sizeof(g_app));
	list_init(&g_app.pktl);
	tmr_init(&g_app.tmr);

	/* Load pcap */
	err = load_pcap(&g_app, pcap_path);
	if (err)
		goto out;

	/* Allocate SIP stack */
	err = sip_alloc(&g_app.sip, NULL, 32, 32, 32,
			"sip-rtp-replay/1.0", NULL, NULL);
	if (err) {
		(void)re_fprintf(stderr, "sip_alloc: %m\n", err);
		goto out;
	}

	struct sa sip_laddr;
	err = net_default_source_addr_get(AF_INET, &sip_laddr);
	if (err) {
		(void)re_fprintf(stderr,
			"net_default_source_addr_get: %m\n", err);
		goto out;
	}
	sa_set_port(&sip_laddr, sip_port);

	err = sip_transp_add(g_app.sip, SIP_TRANSP_UDP, &sip_laddr);
	if (err) {
		(void)re_fprintf(stderr,
			"sip_transp_add UDP %J failed: %m\n",
			&sip_laddr, err);
		goto out;
	}
	(void)re_printf("SIP listening on %J (UDP)\n", &sip_laddr);

	/* Allocate sipsess socket for incoming calls */
	err = sipsess_listen(&g_app.ssock, g_app.sip, 32,
			     conn_handler, &g_app);
	if (err) {
		(void)re_fprintf(stderr, "sipsess_listen: %m\n", err);
		goto out;
	}

	/* Allocate SDP session (address will be updated per call) */
	struct sa sdp_laddr;
	sa_init(&sdp_laddr, AF_INET);
	err = sdp_session_alloc(&g_app.sdp, &sdp_laddr);
	if (err) {
		(void)re_fprintf(stderr, "sdp_session_alloc: %m\n", err);
		goto out;
	}

	/* Add audio media line.  We support the most common codecs;
	 * the SDP negotiation will select the one the caller offers. */
	err = sdp_media_add(&g_app.audio, g_app.sdp,
			    sdp_media_audio, 0, sdp_proto_rtpavp);
	if (err) {
		(void)re_fprintf(stderr, "sdp_media_add: %m\n", err);
		goto out;
	}

	/* PCMU  pt=0  8000 Hz */
	(void)sdp_format_add(NULL, g_app.audio, false,
			     "0",  "PCMU", 8000, 1,
			     NULL, NULL, NULL, false, NULL);
	/* PCMA  pt=8  8000 Hz */
	(void)sdp_format_add(NULL, g_app.audio, false,
			     "8",  "PCMA", 8000, 1,
			     NULL, NULL, NULL, false, NULL);
	/* G.722 pt=9  8000 Hz clock (wideband, 16kHz sampling) */
	(void)sdp_format_add(NULL, g_app.audio, false,
			     "9",  "G722", 8000, 1,
			     NULL, NULL, NULL, false, NULL);
	/* telephone-event pt=101 */
	(void)sdp_format_add(NULL, g_app.audio, false,
			     "101", "telephone-event", 8000, 1,
			     NULL, NULL, NULL, false, "0-16");
	/* Opus  pt=111 48000 Hz stereo */
	(void)sdp_format_add(NULL, g_app.audio, false,
			     "111", "opus", 48000, 2,
			     NULL, NULL, NULL, false, NULL);

	(void)re_printf("ready – waiting for incoming call ...\n");

	/* Run the event loop */
	err = re_main(signal_handler);

out:
	app_destroy(&g_app);
	libre_close();

	if (err && err != EINTR)
		(void)re_fprintf(stderr, "fatal error: %m\n", err);

	return err ? 1 : 0;
}
