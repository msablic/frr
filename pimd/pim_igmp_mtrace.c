/*
 * Multicast traceroute for FRRouting 
 * Copyright (C) 2017  Mladen Sablic
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

#include <zebra.h>

#include "pimd.h"
#include "pim_util.h"
#include "pim_igmp_mtrace.h"

int igmp_mtrace_recv_packet(struct igmp_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct interface *ifp;
	uint16_t recv_checksum;
	uint16_t checksum;

	typedef enum mtrace_subtype {
		MTRACE_SUBTYPE_PACKET,
		MTRACE_SUBTYPE_QUERY,
		MTRACE_SUBTYPE_REQUEST,
		MTRACE_SUBTYPE_RESPONSE
	} mtrace_subtype_t;
	
	mtrace_subtype_t subtype = MTRACE_SUBTYPE_PACKET;
	
	struct pim_interface *pim_ifp;
	struct pim_nexthop nexthop;
	int ret;
	
	ifp = igmp->interface;
	pim_ifp = ifp->info;

	if((unsigned)igmp_msg_len < sizeof(igmp_mtrace_t)) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: too short, len=%d, min=%lu",
			from_str, ifp->name,
			igmp_msg_len, sizeof(igmp_mtrace_t));
		return -1;
	}	


	igmp_mtrace_t* mtracep = (igmp_mtrace_t*)igmp_msg;
	recv_checksum = mtracep->checksum;

	mtracep->checksum = 0;

	checksum = in_cksum(igmp_msg, igmp_msg_len);
	
	if(recv_checksum != checksum) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: checksum mismatch: received=%x computed=%x",
			from_str, ifp->name, recv_checksum,
			checksum);
		return -1;
	}

	/* classify mtrace packet */	
	if((unsigned)igmp_msg_len == sizeof(igmp_mtrace_t)) {
		if(mtracep->type == PIM_IGMP_MTRACE_RESPONSE) {
			zlog_warn(
				"Recv mtrace packet from %s on %s: response without response section",
			from_str, ifp->name);
			return -1;
		}	
		subtype = MTRACE_SUBTYPE_QUERY;
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("Received IGMP multicast traceroute query");
	} 
	else if(((igmp_msg_len - sizeof(igmp_mtrace_t))
		% sizeof(igmp_mtrace_response_t)) == 0) {
		switch(mtracep->type) {
		case PIM_IGMP_MTRACE_QUERY:
			subtype = MTRACE_SUBTYPE_REQUEST;
			break;
		case PIM_IGMP_MTRACE_RESPONSE:
			subtype = MTRACE_SUBTYPE_RESPONSE;
			break;
		}
	}
	else {
		zlog_warn(
			"Recv mtrace packet from %s on %s: invalid length %d" ,
			from_str, ifp->name,  igmp_msg_len);
		return -1;
	}	

	/* checks in order to avoid amplification */
	if(IPV4_CLASS_DE(ntohl(from.s_addr))) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: multicast source %s" ,
			from_str, ifp->name,  inet_ntoa(from));
		return -1;
	}

	if (PIM_DEBUG_IGMP_PACKETS) {
		char grp_str[INET_ADDRSTRLEN];
		char src_str[INET_ADDRSTRLEN];
		char dst_str[INET_ADDRSTRLEN];
		char rsp_str[INET_ADDRSTRLEN];

		zlog_debug(
			"Recv Mtrace packet: hops=%d type=%d size=%d, grp=%s, src=%s, dst=%s rsp=%s",
			mtracep->hops,
			mtracep->type,
			igmp_msg_len,
			inet_ntop(AF_INET,&(mtracep->grp_addr),grp_str,sizeof(grp_str)),
			inet_ntop(AF_INET,&(mtracep->src_addr),src_str,sizeof(src_str)),
			inet_ntop(AF_INET,&(mtracep->dst_addr),dst_str,sizeof(dst_str)),
			inet_ntop(AF_INET,&(mtracep->rsp_addr),rsp_str,sizeof(rsp_str))
			);
	}

	switch(subtype) {
	case MTRACE_SUBTYPE_REQUEST:	
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("Received IGMP multicast traceroute request");
		struct pim_neighbor* neigh = pim_neighbor_find(ifp,from);
		if(neigh == NULL) {
			zlog_warn(
				"Recv mtrace request from %s on %s: no PIM neighbor" ,
				from_str, ifp->name);
				return -1;
		} 
	case MTRACE_SUBTYPE_QUERY:
		ret = pim_nexthop_lookup(pim_ifp->pim, &nexthop, mtracep->src_addr, 1);
		if (PIM_DEBUG_IGMP_PACKETS) {
			if(ret == 0) {
				zlog_debug("pim_nexthop_lookup OK");
			}
			else {
				zlog_debug("not found neightbour");
			}
		}
		break;
	case MTRACE_SUBTYPE_RESPONSE:
		if (PIM_DEBUG_IGMP_PACKETS)
		 	zlog_debug("Received IGMP multicast traceroute response");
		break;
	case MTRACE_SUBTYPE_PACKET:	
		zlog_warn(
			"Recv mtrace packet from %s on %s: unclassified???",
			from_str, ifp->name);
		return -1;
	}
	return -1;
}
