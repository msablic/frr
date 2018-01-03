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

#ifndef PIM_IGMP_MTRACE_H
#define PIM_IGMP_MTRACE_H

#include <zebra.h>

#include "pim_igmp.h"

#ifdef DEV_BUILD
#define PIM_IGMP_MTRACE 1
#else
#define PIM_IGMP_MTRACE 0
#endif

#define MTRACE_UNKNOWN_COUNT	(0xffffffff)

enum mtrace_fwd_code {
	FWD_CODE_NO_ERROR 	= 0x00,
	FWD_CODE_WRONG_IF 	= 0x01,
	FWD_CODE_PRUNE_SENT	= 0x02,
	FWD_CODE_PRUNE_RCVD	= 0x03,
	FWD_CODE_SCOPED		= 0x04,
	FWD_CODE_NO_ROUTE	= 0x05,
	FWD_CODE_WRONG_LAST_HOP	= 0x06,
	FWD_CODE_NOT_FORWARDING	= 0x07,
	FWD_CODE_REACHED_RP	= 0x08,
	FWD_CODE_RPF_IF		= 0x09,
	FWD_CODE_NO_MULTICAST	= 0x0A,
	FWD_CODE_INFO_HIDDEN	= 0x0B,
	FWD_CODE_NO_SPACE	= 0x81,
	FWD_CODE_OLD_ROUTER	= 0x82,
	FWD_CODE_ADMIN_PROHIB	= 0x83
};

enum mtrace_rtg_proto {
	RTG_PROTO_DVMRP		= 1,
	RTG_PROTO_MOSPF		= 2,
	RTG_PROTO_PIM		= 3,
	RTG_PROTO_CBT		= 4,
	RTG_PROTO_PIM_SPECIAL	= 5,
	RTG_PROTO_PIM_STATIC	= 6,
	RTG_PROTO_DVMRP_STATIC 	= 7,
	RTG_PROTO_PIM_MBGP	= 8,
	RTG_PROTO_CBT_SPECIAL	= 9,
	RTG_PROTO_CBT_STATIC	= 10,
	RTG_PROTO_PIM_ASSERT	= 11,
};

struct igmp_mtrace_rsp {
	uint32_t arrival;
	struct in_addr incoming;
	struct in_addr outgoing;
	struct in_addr prev_hop;
	uint32_t in_count;
	uint32_t out_count;
	uint32_t total;
	uint32_t rtg_proto : 8;
	uint32_t fwd_ttl  : 8;
	/* little endian order for next three fields */
	uint32_t src_mask : 6;
	uint32_t s : 1;
	uint32_t mbz : 1;
	uint32_t fwd_code : 8;
} __attribute__((packed));

struct igmp_mtrace {
	uint8_t type;
	uint8_t hops;
	uint16_t checksum;
	struct in_addr grp_addr;
	struct in_addr src_addr;
	struct in_addr dst_addr;
	struct in_addr rsp_addr;
	uint32_t rsp_ttl : 8;
	uint32_t qry_id : 24;
	struct igmp_mtrace_rsp rsp[0];
} __attribute__((packed));

int igmp_mtrace_recv_qry_req(struct igmp_sock *igmp, struct ip *ip_hdr, struct in_addr from,
			     const char *from_str, char *igmp_msg, int igmp_msg_len);

int igmp_mtrace_recv_response(struct igmp_sock *igmp, struct ip *ip_hdr, struct in_addr from,
			      const char *from_str, char *igmp_msg, int igmp_msg_len);

#endif /* PIM_IGMP_MTRACE_H */
