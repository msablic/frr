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

static void mtrace_rsp_init(struct igmp_mtrace_rsp *mtrace_rspp) {
	mtrace_rspp->arrival = 0;
	mtrace_rspp->incoming.s_addr = 0;
	mtrace_rspp->outgoing.s_addr = 0;
	mtrace_rspp->prev_hop.s_addr = 0;
	mtrace_rspp->in_count = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->out_count = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->total = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->rtg_proto = 0;
	mtrace_rspp->fwd_ttl = 0;
	mtrace_rspp->mbz = 0;
	mtrace_rspp->s = 0;
	mtrace_rspp->src_mask = 0;
	mtrace_rspp->fwd_code = FWD_CODE_NO_ERROR;
}

static void mtrace_debug(struct pim_interface *pim_ifp, struct igmp_mtrace *mtracep, int mtrace_len)
{
	char inc_str[INET_ADDRSTRLEN];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	char rsp_str[INET_ADDRSTRLEN];

	zlog_debug(
		"Recv mtrace packet incoming on %s: hops=%d type=%d size=%d, grp=%s, src=%s,"
		" dst=%s rsp=%s ttl=%d qid=%ud",
		inet_ntop(AF_INET,&(pim_ifp->primary_address),inc_str,sizeof(inc_str)),
		mtracep->hops,
		mtracep->type,
		mtrace_len,
		inet_ntop(AF_INET,&(mtracep->grp_addr),grp_str,sizeof(grp_str)),
		inet_ntop(AF_INET,&(mtracep->src_addr),src_str,sizeof(src_str)),
		inet_ntop(AF_INET,&(mtracep->dst_addr),dst_str,sizeof(dst_str)),
		inet_ntop(AF_INET,&(mtracep->rsp_addr),rsp_str,sizeof(rsp_str)),
		mtracep->rsp_ttl,
		ntohl(mtracep->qry_id)
	);
	if((unsigned)mtrace_len > sizeof(struct igmp_mtrace)) {

		int i;

		int responses = mtrace_len - sizeof(struct igmp_mtrace);

		if((responses % sizeof(struct igmp_mtrace_rsp)) != 0)
			zlog_debug("Mtrace response block of wrong length");

		responses = responses / sizeof(struct igmp_mtrace_rsp);

		for (i = 0; i < responses; i++)
		{
			char inc_str[INET_ADDRSTRLEN];
			char out_str[INET_ADDRSTRLEN];
			char prv_str[INET_ADDRSTRLEN];
			zlog_debug("Recv mtrace qid=%ud rsp=%d arrival=%x"
				" incoming=%s outgoing=%s prev_hop=%s proto=%d fwd_code=%d",
				ntohl(mtracep->qry_id),
				i,
				mtracep->rsp[i].arrival,
				inet_ntop(AF_INET,&(mtracep->rsp[i].incoming),inc_str,sizeof(inc_str)),
				inet_ntop(AF_INET,&(mtracep->rsp[i].outgoing),out_str,sizeof(out_str)),
				inet_ntop(AF_INET,&(mtracep->rsp[i].prev_hop),prv_str,sizeof(prv_str)),
				mtracep->rsp[i].rtg_proto,
				mtracep->rsp[i].fwd_code
			);
		}
	}
}

/* 5.1 Query Arrival Time */
static uint32_t query_arrival_time()
{
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

/* 6.5 Sending Traceroute Responses */
static int mtrace_send_response(struct pim_instance *pim, struct igmp_mtrace *mtracep, size_t mtrace_len)
{
	struct pim_nexthop nexthop;
	int ret;
	struct igmp_sock *igmp;
	char rsp_str[INET_ADDRSTRLEN];
	char igmp_str[INET_ADDRSTRLEN];

	/* TODO: should use unicast rib lookup */
	ret = pim_nexthop_lookup(pim, &nexthop, mtracep->rsp_addr, 1);

	if(ret != 0) {
		zlog_warn("Dropped response qid=%ud, no route to response address",
			mtracep->qry_id
		);
		return -1;
	}

	igmp = get_primary_igmp_sock(nexthop.interface->info);

	mtracep->type = PIM_IGMP_MTRACE_RESPONSE;

	mtracep->checksum = 0;
	mtracep->checksum = in_cksum((char*)mtracep,mtrace_len);

	if (PIM_DEBUG_IGMP_PACKETS)
		zlog_debug("Sending mtrace response to %s on %s",
			inet_ntop(AF_INET, &mtracep->rsp_addr, rsp_str,sizeof(rsp_str)),
			inet_ntop(AF_INET, &igmp->ifaddr, igmp_str,sizeof(igmp_str))
		);

	return mtrace_send_packet(igmp,(char*)mtracep,mtrace_len,mtracep->rsp_addr,mtracep->grp_addr);
}

int igmp_mtrace_recv_qry_req(struct igmp_sock *igmp, struct ip *ip_hdr, struct in_addr from,
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
			/* TODO: forwarding code here */
			zlog_warn("Unicast addressed mtrace packet dropped");
			return -1;
		}
	}
			
	ifp = igmp->interface;

	if((unsigned)igmp_msg_len < sizeof(struct igmp_mtrace)) {
		zlog_warn(
			"Recv mtrace packet from %s on %s: too short, len=%d, min=%lu",
			from_str, ifp->name,
			igmp_msg_len, sizeof(struct igmp_mtrace));
		return -1;
	}	


	struct igmp_mtrace* mtracep = (struct igmp_mtrace*)igmp_msg;

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

	if (PIM_DEBUG_IGMP_PACKETS)
		mtrace_debug(pim_ifp,mtracep,igmp_msg_len);

	enum mtrace_fwd_code fwd_code = FWD_CODE_NO_ERROR;
	
	/* Classify mtrace packet, check if it is a query */	
	if((unsigned)igmp_msg_len == sizeof(struct igmp_mtrace)) {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("Received IGMP multicast traceroute query");

		/* 6.1.1  Packet verification */
		if(!pim_if_connected_to_source(ifp, mtracep->dst_addr)) {
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
	}
	else if(((igmp_msg_len - sizeof(struct igmp_mtrace))
			% sizeof(struct igmp_mtrace_rsp)) == 0) {
		size_t response_len = igmp_msg_len - sizeof(struct igmp_mtrace);

		if(response_len != 0)
			last_rsp_ind = response_len/sizeof(struct igmp_mtrace_rsp);
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

	/* 6.2.2. Normal Processing */

	/* allocate mtrace request buffer */
	size_t mtrace_buf_len = igmp_msg_len + sizeof(struct igmp_mtrace_rsp);

	char mtrace_buf[mtrace_buf_len];

	memcpy(mtrace_buf,igmp_msg,igmp_msg_len);

	struct igmp_mtrace* mtracerp = (struct igmp_mtrace*)mtrace_buf;

	mtrace_rsp_init(&mtracerp->rsp[last_rsp_ind]);

	/* 6.2.2. 1. */

	mtracerp->rsp[last_rsp_ind].arrival = htonl(query_arrival_time());
	mtracerp->rsp[last_rsp_ind].outgoing.s_addr = pim_ifp->primary_address.s_addr;
	mtracerp->rsp[last_rsp_ind].out_count = htonl(MTRACE_UNKNOWN_COUNT);

	/* 6.2.2. 2. Attempt to determine forwarding information */

	nh_addr.s_addr = 0;
	
	ret = pim_nexthop_lookup(pim_ifp->pim, &nexthop, mtracep->src_addr, 1);

	if(ret == 0) {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("mtrace pim_nexthop_lookup OK");

		char nexthop_str[INET_ADDRSTRLEN];

		zlog_warn("mtrace next_hop=%s",
			inet_ntop(nexthop.mrib_nexthop_addr.family,
				&nexthop.mrib_nexthop_addr.u.prefix, nexthop_str,sizeof(nexthop_str))
		);
		if(nexthop.mrib_nexthop_addr.family == AF_INET) {
			nh_addr.s_addr = nexthop.mrib_nexthop_addr.u.prefix4.s_addr;
		}
	}
	/* 6.4 Forwarding Traceroute Requests: ... Otherwise, ... */
	else {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("mtrace not found neighbor");
		if(!fwd_code)
			mtracerp->rsp[last_rsp_ind].fwd_code = FWD_CODE_NO_ROUTE;
		else
			mtracerp->rsp[last_rsp_ind].fwd_code = fwd_code;
		/* 6.5 Sending Traceroute Responses */
		return mtrace_send_response(pim_ifp->pim,mtracerp,mtrace_buf_len);
	}


	struct igmp_sock *igmp_out = get_primary_igmp_sock(nexthop.interface->info);
	
	mtracerp->rsp[last_rsp_ind].incoming.s_addr = igmp_out->ifaddr.s_addr;
	mtracerp->rsp[last_rsp_ind].prev_hop.s_addr = nh_addr.s_addr;
	mtracerp->rsp[last_rsp_ind].in_count = htonl(MTRACE_UNKNOWN_COUNT);
	mtracerp->rsp[last_rsp_ind].total = htonl(MTRACE_UNKNOWN_COUNT);
	mtracerp->rsp[last_rsp_ind].rtg_proto = RTG_PROTO_PIM; 
	mtracerp->rsp[last_rsp_ind].s = 1; 
	mtracerp->rsp[last_rsp_ind].src_mask = 32; 

	if (nh_addr.s_addr == 0) {
		/* reached source? */
		if(pim_if_connected_to_source(nexthop.interface, mtracep->src_addr)) {
			return mtrace_send_response(pim_ifp->pim,mtracerp,mtrace_buf_len);
		}
		else {
			/* 6.4 Forwarding Traceroute Requests: Previous-hop router not known */
			inet_aton(MCAST_ALL_ROUTERS,&nh_addr);
		}
	}	

	mtracerp->checksum = 0;

	mtracerp->checksum = in_cksum(mtrace_buf,mtrace_buf_len);
	
	return mtrace_send_packet(igmp_out, mtrace_buf,mtrace_buf_len,nh_addr,mtracep->grp_addr);
}

int igmp_mtrace_recv_response(struct igmp_sock *igmp, struct ip *ip_hdr, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct pim_interface *pim_ifp;

	pim_ifp = igmp->interface->info;

	struct igmp_mtrace* mtracep = (struct igmp_mtrace*)igmp_msg;

	if (PIM_DEBUG_IGMP_PACKETS)
		mtrace_debug(pim_ifp,mtracep,igmp_msg_len);

	/* TODO: forward or receive responses */

	return -1;
}
