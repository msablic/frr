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

/* 5.1 Query Arrival Time */
static uint32_t query_arrival_time() {
	struct timeval tv;
	uint32_t qat;

	if(gettimeofday(&tv,NULL) < 0) {
		zlog_warn("Query arrival time lookup failed: errno=%d: %s",
			errno, safe_strerror(errno)
		);
		return 0;
	}
	/* not sure second offset correct, as I get different value */
	qat = ((tv.tv_sec + 32384) << 16) + ((tv.tv_usec << 10) / 15625);

	return qat;
}

static int mtrace_send_packet(struct igmp_sock *igmp, char *mtrace_buf, size_t mtrace_buf_len,
				struct in_addr dst_addr, struct in_addr group_addr )
{
	struct sockaddr_in to;
	socklen_t tolen;
	ssize_t sent;
	struct interface *ifp;

	ifp = igmp->interface;
		
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst_addr;
	tolen = sizeof(to);

	sent = sendto(igmp->fd, mtrace_buf, mtrace_buf_len, MSG_DONTWAIT,
		(struct sockaddr *)&to, tolen);

	if (sent != (ssize_t)mtrace_buf_len) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str, sizeof(group_str));
		if (sent < 0) {
			zlog_warn(
			"Send mtrace request failed for %s on %s: group=%s msg_size=%zd: errno=%d: %s",
			dst_str, ifp->name, group_str, mtrace_buf_len, errno, safe_strerror(errno)
			);
		} else {
			zlog_warn(
				"Send mtrace request failed for %s on %s: group=%s msg_size=%zd: sent=%zd",
				dst_str, ifp->name, group_str, mtrace_buf_len, sent
			);
		}
		return -1;
	}
	return 0;
}

static struct igmp_sock *get_primary_igmp_sock(struct pim_interface *pim_ifp)
{
	struct listnode *sock_node;
	struct igmp_sock *igmp_out;
	
	for(ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node, igmp_out)) {
		if(igmp_out->ifaddr.s_addr == pim_ifp->primary_address.s_addr) {
			break;
		}
	}
	if(igmp_out == NULL) {
		char pim_str[INET_ADDRSTRLEN];
		zlog_warn("Not found output IGMP socket on PIM interface %s for mtrace packet",
			inet_ntop(AF_INET,
				&pim_ifp->primary_address,
				pim_str,sizeof(pim_str))
		);
		return NULL;
	}
	return igmp_out;
}

int igmp_mtrace_recv_packet(struct igmp_sock *igmp, struct ip *ip_hdr, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	static uint32_t query_id = 0, query_src = 0;
	int forward = 1;
	struct interface *ifp;
	uint16_t recv_checksum;
	uint16_t checksum;
	struct pim_interface *pim_ifp;
	struct pim_nexthop nexthop;
	struct in_addr nh_addr;
	int ret;
	int last_rsp_ind = 0;
	
	pim_ifp = igmp->interface->info;


	/* 
	 * 6. Router Behaviour
	 * Check if mtrace packet is addressed elsewhere and forward, if applicable
	 */
	if(!IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr))) {
		FOR_ALL_INTERFACES(pim_ifp->pim->vrf, ifp) {
			struct listnode *cnode;
			struct connected *connected;

			for(ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, connected)) {
				struct prefix_ipv4 *p;

				p = (struct prefix_ipv4 *)connected->address;

				if (p->family != AF_INET)
					continue;

				if(IPV4_ADDR_CMP(&p->prefix, &ip_hdr->ip_dst) == 0) {
					forward = 0;
					break;
				}
			}
			if(!forward)
				break;
		}

		if(forward) {
			/* forwarding code here */
			zlog_warn("Unicast addressed mtrace packet dropped");
			return -1;
		}
	}
			
	ifp = igmp->interface;

	if((unsigned)igmp_msg_len < sizeof(struct igmp_mtrace_qry)) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: too short, len=%d, min=%lu",
			from_str, ifp->name,
			igmp_msg_len, sizeof(struct igmp_mtrace_qry));
		return -1;
	}	


	struct igmp_mtrace_qry* mtracep = (struct igmp_mtrace_qry*)igmp_msg;

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

	if (PIM_DEBUG_IGMP_PACKETS) {
		char inc_str[INET_ADDRSTRLEN];
		char grp_str[INET_ADDRSTRLEN];
		char src_str[INET_ADDRSTRLEN];
		char dst_str[INET_ADDRSTRLEN];
		char rsp_str[INET_ADDRSTRLEN];

		zlog_debug(
			"Recv Mtrace packet incoming on %s: hops=%d type=%d size=%d, grp=%s, src=%s,"
			" dst=%s rsp=%s ttl=%d id=%d",
			inet_ntop(AF_INET,&(pim_ifp->primary_address),inc_str,sizeof(inc_str)),
			mtracep->hops,
			mtracep->type,
			igmp_msg_len,
			inet_ntop(AF_INET,&(mtracep->grp_addr),grp_str,sizeof(grp_str)),
			inet_ntop(AF_INET,&(mtracep->src_addr),src_str,sizeof(src_str)),
			inet_ntop(AF_INET,&(mtracep->dst_addr),dst_str,sizeof(dst_str)),
			inet_ntop(AF_INET,&(mtracep->rsp_addr),rsp_str,sizeof(rsp_str)),
			mtracep->rsp_ttl,
			ntohl(mtracep->qry_id)
			);
	}

	enum mtrace_fwd_code fwd_code = FWD_CODE_NO_ERROR;
	
	/* Classify mtrace packet, check if it is a query */	
	if((unsigned)igmp_msg_len == sizeof(struct igmp_mtrace_qry)) {
		switch(mtracep->type) {
		/* wrong type */
		case PIM_IGMP_MTRACE_RESPONSE: {
			zlog_warn(
				"Recv mtrace packet from %s on %s: response without response section",
			from_str, ifp->name);
			return -1;
		}
		/* start query processing */
		case PIM_IGMP_MTRACE_QUERY_REQUEST: {
			if (PIM_DEBUG_IGMP_PACKETS)
				zlog_debug("Received IGMP multicast traceroute query");

			/* 6.1.1  Packet verification */
			if(!pim_if_connected_to_source(ifp, from)) {
				if(IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr)))  {
					if (PIM_DEBUG_IGMP_PACKETS)
						zlog_debug("Dropping multicast query on wrong interface");
					return -1;
				}
				/* Unicast query on wrong interface */
				fwd_code = FWD_CODE_WRONG_IF;
			}
			if(query_id == mtracep->qry_id && query_src == from.s_addr) {
				if (PIM_DEBUG_IGMP_PACKETS)
					zlog_debug("Dropping multicast query with duplicate source and id");
				return -1;
			}
			query_id = mtracep->qry_id;
			query_src = from.s_addr;
			break;
		}
		default:
			zlog_warn(
				"Dropping mtrace packet from %s on %s of type %d",
				from_str, ifp->name, mtracep->type);
			return -1;
		}
	}
	else if(((igmp_msg_len - sizeof(struct igmp_mtrace_qry))
			% sizeof(struct igmp_mtrace_rsp)) == 0) {
		switch(mtracep->type) {
		case PIM_IGMP_MTRACE_QUERY_REQUEST: {

	        	size_t response_len = igmp_msg_len - sizeof(struct igmp_mtrace_qry);

			if(response_len != 0)
				last_rsp_ind = response_len/sizeof(struct igmp_mtrace_rsp);
			break;
		}
		case PIM_IGMP_MTRACE_RESPONSE:
			/* forward response here */
			return 0;	
		}
	}
	else {
		zlog_warn(
			"Recv mtrace packet from %s on %s: invalid length %d" ,
			from_str, ifp->name,  igmp_msg_len);
		return -1;
	}	

	/* 6.2.1 Packet Verification - drop not link-local multicast */
	if(IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr)) 
	 	&& !IPV4_MC_LINKLOCAL(ntohl(ip_hdr->ip_dst.s_addr))) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: not link-local multicast %s" ,
			from_str, ifp->name,  inet_ntoa(ip_hdr->ip_dst));
		return -1;
	}

	nh_addr.s_addr = 0;
	
	ret = pim_nexthop_lookup(pim_ifp->pim, &nexthop, mtracep->src_addr, 1);

	if(ret == 0) {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("pim_nexthop_lookup OK");

		char nexthop_str[INET_ADDRSTRLEN];

		zlog_warn("next_hop=%s",
			inet_ntop(nexthop.mrib_nexthop_addr.family,
				&nexthop.mrib_nexthop_addr.u.prefix, nexthop_str,sizeof(nexthop_str))
		);
		if(nexthop.mrib_nexthop_addr.family == AF_INET) {
			nh_addr.s_addr = nexthop.mrib_nexthop_addr.u.prefix4.s_addr;
		}
	}
	else {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("not found neighbor");
	}

	if(igmp_msg_len == sizeof(struct igmp_mtrace_qry)
		&& nh_addr.s_addr == 0
		&& fwd_code == FWD_CODE_NO_ERROR) {
		fwd_code = FWD_CODE_RPF_IF;
	}

	size_t mtrace_buf_len = igmp_msg_len + sizeof(struct igmp_mtrace_rsp);

	char mtrace_buf[mtrace_buf_len];

	memcpy(mtrace_buf,igmp_msg,igmp_msg_len);
		
	struct igmp_mtrace_qry* mtrace_p = (struct igmp_mtrace_qry*)mtrace_buf;

	mtrace_p->rsp[last_rsp_ind].arrival = htonl(query_arrival_time());

	mtrace_p->checksum = 0;

	mtrace_p->checksum = in_cksum(mtrace_buf,mtrace_buf_len);
	
	struct igmp_sock *igmp_out = get_primary_igmp_sock(nexthop.interface->info);

	return mtrace_send_packet(igmp_out, mtrace_buf,mtrace_buf_len,nh_addr,mtracep->grp_addr);
}


