/*
 * Multicast Traceroute for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef __linux__

#include "pim_igmp_mtrace.h"

#include "checksum.h"
#include "mtracebis_routeget.h"

#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <net/if.h>

#define MTRACE_TIMEOUT (5)

#define IP_HDR_LEN (sizeof(struct ip))
#define IP_RA_LEN (4)
#define MTRACE_BUF_LEN (MTRACE_HDR_SIZE + (MTRACE_MAX_HOPS * MTRACE_RSP_SIZE))
#define IP_AND_MTRACE_BUF_LEN (IP_HDR_LEN + IP_RA_LEN + MTRACE_BUF_LEN)

static void usage(const char *name)
{
	fprintf(stderr, "%s SOURCE\n", name);
}

static int send_query(int fd, struct in_addr to_addr,
		      struct igmp_mtrace *mtrace)
{
	struct sockaddr_in to;
	socklen_t tolen;
	int sent;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = to_addr;
	tolen = sizeof(to);

	sent = sendto(fd, (char *)mtrace, sizeof(*mtrace), MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);

	if (sent < 1)
		return -1;
	return 0;
}

static void print_query(struct igmp_mtrace *mtrace)
{
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	char grp_str[INET_ADDRSTRLEN];

	printf("* Mtrace from %s to %s via group %s\n",
	       inet_ntop(AF_INET, &mtrace->src_addr, src_str, sizeof(src_str)),
	       inet_ntop(AF_INET, &mtrace->dst_addr, dst_str, sizeof(dst_str)),
	       inet_ntop(AF_INET, &mtrace->grp_addr, grp_str, sizeof(grp_str)));
}

static int recv_response(int fd, long msec)
{
	int recvd;
	char mtrace_buf[IP_AND_MTRACE_BUF_LEN];
	struct ip *ip;
	struct igmp_mtrace *mtrace;
	int mtrace_len;
	u_short sum;

	recvd = recvfrom(fd, mtrace_buf, IP_AND_MTRACE_BUF_LEN, 0, NULL, 0);

	if (recvd < 1) {
		fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
		return -1;
	}

	if (recvd < (signed)sizeof(struct ip)) {
		fprintf(stderr, "no ip header\n");
		return -1;
	}

	ip = (struct ip *)mtrace_buf;

	if (ip->ip_v != 4) {
		fprintf(stderr, "IP not version 4\n");
		return -1;
	}

	sum = ip->ip_sum;
	ip->ip_sum = 0;

	if (sum != in_cksum(ip, ip->ip_hl * 4)) {
		return -1;
	}
	mtrace = (struct igmp_mtrace *)(mtrace_buf + (4 * ip->ip_hl));

	mtrace_len = ntohs(ip->ip_len) - ip->ip_hl * 4;

	if (mtrace_len < (signed)MTRACE_HDR_SIZE) {
		return -1;
	}

	sum = mtrace->checksum;
	mtrace->checksum = 0;
	if (sum != in_cksum(mtrace, mtrace_len)) {
		fprintf(stderr, "mtrace checksum wrong\n");
		return -1;
	}

	if (mtrace->type != PIM_IGMP_MTRACE_RESPONSE) {
		return -1;
	}

	printf("%ld ms received response.\n", msec);
	return 0;
}

static int wait_for_response(int fd)
{
	fd_set readfds;
	struct timeval timeout;
	int ret = -1;
	long msec, rmsec, tmsec;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	memset(&timeout, 0, sizeof(timeout));

	timeout.tv_sec = MTRACE_TIMEOUT;

	tmsec = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
	do {
		if ((ret = select(fd + 1, &readfds, NULL, NULL, &timeout))
		    <= 0) {
			return ret;
		}
		rmsec = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
		msec = tmsec - rmsec;
	} while (recv_response(fd, msec) != 0);

	return ret;
}

int main(int argc, const char *argv[])
{
	struct in_addr mc_source;
	struct in_addr iface_addr;
	struct in_addr gw_addr;
	struct in_addr mtrace_addr;
	struct igmp_mtrace mtrace;
	int hops = 255;
	int maxhops = 5;
	int perhop = 3;
	int ifindex;
	int unicast = 1;
	int ttl = 64;
	int fd = -1;
	int ret = -1;
	int i, j;
	int gotresponse = 0;
	char ifname[IF_NAMESIZE];
	char ip_str[INET_ADDRSTRLEN];

	mtrace_addr.s_addr = inet_addr("224.0.1.32");

	uid_t uid = getuid();

	if (uid != 0) {
		printf("must run as root\n");
		exit(EXIT_FAILURE);
	}

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (inet_pton(AF_INET, argv[1], &mc_source) != 1) {
		usage(argv[0]);
		fprintf(stderr, "%s: %s not a valid IPv4 address\n", argv[0],
			argv[1]);
		exit(EXIT_FAILURE);
	}

	if ((ifindex = routeget(mc_source, &iface_addr, &gw_addr)) < 0) {
		fprintf(stderr, "%s: failed to get route to source %s\n",
			argv[0], argv[1]);
		exit(EXIT_FAILURE);
	}

	if (if_indextoname(ifindex, ifname) == NULL) {
		fprintf(stderr, "%s: if_indextoname error: %s\n", argv[0],
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* zero mtrace struct */
	memset((char *)&mtrace, 0, sizeof(mtrace));

	/* set up query */
	mtrace.type = PIM_IGMP_MTRACE_QUERY_REQUEST;
	mtrace.hops = hops;
	mtrace.checksum = 0;
	mtrace.grp_addr.s_addr = 0;
	mtrace.src_addr = mc_source;
	mtrace.dst_addr = iface_addr;
	mtrace.rsp_addr = unicast ? iface_addr : mtrace_addr;
	mtrace.rsp_ttl = ttl;
	mtrace.qry_id = 0xffffff & time(NULL);

	mtrace.checksum = in_cksum(&mtrace, sizeof(mtrace));

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);

	if (fd < 1) {
		fprintf(stderr, "%s: socket error: %s\n", argv[0],
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			 strlen(ifname));

	if (ret < 0) {
		fprintf(stderr, "%s: setsockopt error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}

	print_query(&mtrace);
	if (send_query(fd, gw_addr, &mtrace) < 0) {
		fprintf(stderr, "%s: sendto error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}
	printf("Querying full reverse path...\n");
	if ((ret = wait_for_response(fd)) > 0) {
		ret = 0;
		goto close_fd;
	}
	if (ret < 0) {
		fprintf(stderr, "%s: select error: %s\n", argv[0],
			strerror(errno));
		ret = EXIT_FAILURE;
		goto close_fd;
	}
	printf(" * ");
	printf("switching to hop-by-hop:\n");
	printf("%3d  ? (%s)\n", 0,
	       inet_ntop(AF_INET, &mtrace.dst_addr, ip_str, sizeof(ip_str)));
	for (i = 1; i < maxhops; i++) {
		printf("%3d ", -i);
		mtrace.hops = i;
		mtrace.checksum = 0;
		mtrace.checksum = in_cksum(&mtrace, sizeof(mtrace));
		for (j = 0; j < perhop; j++) {
			if (send_query(fd, gw_addr, &mtrace) < 0) {
				fprintf(stderr, "%s: sendto error: %s\n",
					argv[0], strerror(errno));
				ret = EXIT_FAILURE;
				goto close_fd;
			}
			if ((ret = wait_for_response(fd)) > 0) {
				gotresponse = 1;
				continue;
			}
			printf(" *");
		}
		printf("\n");
	}
	if (!gotresponse) {
		printf("...giving up\n");
		printf("Timed out receiving responses\n");
	}
	ret = 0;
close_fd:
	close(fd);
	exit(ret);
}

#else /* __linux__ */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	printf("%s implemented only for GNU/Linux\n", argv[0]);
	exit(0);
}

#endif /* __linux__ */
