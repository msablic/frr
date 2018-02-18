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

#include "mtracebis_routeget.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <net/if.h>

int routeget(struct in_addr dst, struct in_addr *src, struct in_addr *gw)
{
	FILE *fp;
	int ret;
	int scand;
	unsigned int ifindex;
	char cmd[80];
	char dst_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char if_str[IF_NAMESIZE];
	char gw_str[INET_ADDRSTRLEN];
	char dummy[80];

	inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));

	sprintf(cmd, "ip route get %s", dst_str);

	fp = popen(cmd, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to run command 'ip'\n");
		return -1;
	}
	scand = fscanf(fp, "%s %s %s %s %s %s %s\n", dummy, dummy, gw_str,
		       dummy, if_str, dummy, src_str);
	ret = pclose(fp);
	if (ret < 0) {
		fprintf(stderr, "%s failed: %s\n", cmd, strerror(errno));
		return -1;
	}
	if (scand != 7)
		return -1;
	if (src)
		src->s_addr = inet_addr(src_str);
	if (gw)
		gw->s_addr = inet_addr(gw_str);
	ifindex = if_nametoindex(if_str);
	if (ifindex == 0) {
		fprintf(stderr, "if_nametoindex: %s\n", strerror(errno));
		return -1;
	}
	return ifindex;
}

#endif /* __linux__ */
