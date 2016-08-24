/*
 * connect to an HTTP server and request HEAD / HTTP/1.0 every so often...
 *
 * -jduck
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/select.h>


#ifndef LOCAL_PORT
#define LOCAL_PORT 37373
#endif


int get_socket(void);
int lookup_host(char *hostname, struct sockaddr_in *addr);


int main(int argc, char *argv[])
{
	struct timeval connected, requested, now, diff;
	int sd, port = 80;
	struct sockaddr_in srv;
	const char *request = "HEAD / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
	int request_made = 0;
	int reqlen;

	reqlen = strlen(request);

	if (argc < 2) {
		printf("usage: client <server> [<port>]\n");
		return 1;
	}
	if (argc > 2)
		port = atoi(argv[2]);

	if (!lookup_host(argv[1], &srv))
		return 1;
	srv.sin_port = htons(port);

	if ((sd = get_socket()) == -1)
		return 1;

	/* connect to the host */
	while (1) {
		if (connect(sd, (struct sockaddr *)&srv, sizeof(srv)) == -1) {
			perror("connect");
			sleep(5);
			continue;
		}

		gettimeofday(&connected, NULL);
		printf("[*] connected from port %u to %s:%d on sd %d\n", LOCAL_PORT, argv[1], port, sd);

		requested.tv_sec = connected.tv_sec - 59;

		while (1) {
			ssize_t nrw;
			char buf[1048576];
			int sret;
			fd_set rfds;

			/* write the request every so often */
			gettimeofday(&now, NULL);
			timersub(&now, &requested, &diff);
			if (diff.tv_sec >= 59) {
				printf("    sending request...\n");
				nrw = write(sd, request, reqlen);
				if (nrw != reqlen) {
					if (nrw < 0)
						perror("write");
					else
						printf("short write (%d)!\n", (int)nrw);
					break;
				}
				gettimeofday(&requested, NULL);
				request_made = 1;
			}
			
			/* see if we should read the response */
			FD_ZERO(&rfds);
			FD_SET(fileno(stdout), &rfds);
			FD_SET(sd, &rfds);
			diff.tv_sec = 1;
			diff.tv_usec = 0;
			sret = select(sd + 1, &rfds, NULL, NULL, &diff);
			if (sret == -1) {
				perror("select");
				break;
			}

			if (sret > 0) {
				if (FD_ISSET(fileno(stdout), &rfds)) {
					/* force a request */
					nrw = read(fileno(stdin), buf, sizeof(buf));
					requested.tv_sec -= 59;
				}
				if (FD_ISSET(sd, &rfds)) {
					nrw = read(sd, buf, sizeof(buf));
					if (nrw > 0) {
						gettimeofday(&now, NULL);
						timersub(&now, &requested, &diff);
						printf("    read %d bytes of data in %lu %lu seconds\n", (int)nrw, diff.tv_sec, diff.tv_usec);
						if (!request_made) {
							printf("unexpected data:\n");
							write(fileno(stdout), buf, nrw);
						}
						else
							 request_made = 0;
						memcpy(&requested, &now, sizeof(requested));
					} else {
						if (nrw < 0)
							perror("read");
						else
							printf("connection closed?!\n");
						break;
					}
				}
			}
		}

		gettimeofday(&now, NULL);
		timersub(&now, &connected, &diff);
		printf("[*] previous connection lasted %lu %lu seconds. trying to reconnect...\n", diff.tv_sec, diff.tv_usec);

		/* re-try to connect */
		close(sd);
		sd = get_socket();
	}

	return 0;
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


int get_socket(void)
{
	struct sockaddr_in la;
	int sd, lalen, opt;

    /* open the socket */
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
        return -1;
    }

    opt = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sd);
        return -1;
    }

    memset(&la, 0, sizeof(la));
	la.sin_port = htons(LOCAL_PORT);
	la.sin_addr.s_addr = INADDR_ANY;

	lalen = sizeof(la);
	if (bind(sd, (struct sockaddr *) &la, lalen) == -1) {
		perror("bind");
        close(sd);
        return -1;
    }

    return sd;
}
