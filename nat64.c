/*
 *  nat64.c -- IPv4/IPv6 header rewriting routines
 *
 *  part of TAYGA <https://github.com/apalrd/tayga>
 *  Copyright (C) 2010  Nathan Lutchansky <lutchann@litech.org>
 *  Copyright (C) 2025  Andrew Palardy <andrew@apalrd.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include "tayga.h"

/* Protocol headers */
struct ip6_data {
    struct tun_pi pi;
    struct ip6 ip6;
    struct ip6_frag ip6_frag;
};

struct ip6_icmp {
    struct tun_pi pi;
    struct ip6 ip6;
    struct tayga_icmp icmp;
};

struct ip6_error {
    struct tun_pi pi;
    struct ip6 ip6;
    struct tayga_icmp icmp;
    struct ip6 ip6_em;
};

struct ip4_data {
    struct tun_pi pi;
    struct ip4 ip4;
};

struct ip4_icmp {
    struct tun_pi pi;
    struct ip4 ip4;
    struct tayga_icmp icmp;
};

struct ip4_error {
    struct tun_pi pi;
    struct ip4 ip4;
    struct tayga_icmp icmp;
    struct ip4 ip4_em;
};

/**
 * @brief Print an IPv4 packet to the log
 *
 * @param err Bitmask of LOG_OPT to report this packet
 * @param p   struct pkt which encountered the error
 * @param msg string message to include in the log
 */
static void log_pkt4(int err, struct pkt *p, const char *msg)
{
	const char * type = "";
	if	   (gcfg.log_opts & err & LOG_OPT_SELF) 	type = "SELF";
	else if(gcfg.log_opts & err & LOG_OPT_DROP) 	type = "DROP";
	else if(gcfg.log_opts & err & LOG_OPT_REJECT) 	type = "REJECT";
	else if(gcfg.log_opts & err & LOG_OPT_ICMP) 	type = "ICMP";
	else return;

	/* Convert the src / dest IPv4 to strings */
	char saddr[INET_ADDRSTRLEN],daddr[INET_ADDRSTRLEN];
	const char * ret;
	ret = inet_ntop(AF_INET,&p->ip4->src,saddr,sizeof(saddr));
	if(!ret) {
		/* ntop got an error */
		sprintf(saddr,"ERROR:%d",errno);
	}
	ret = inet_ntop(AF_INET,&p->ip4->dest,daddr,sizeof(daddr));
	if(!ret) {
		/* ntop got an error */
		sprintf(daddr,"ERROR:%d",errno);
	}
	/* Build final string */
	int sev = LOG_INFO;
	if(err & (LOG_OPT_DROP | LOG_OPT_REJECT)) sev = LOG_NOTICE;
	slog(sev,"%s: [v4] [%s]->[%s] (%d bytes) (proto %d) %s\n",
		type, saddr, daddr, (p->header_len + p->data_len),p->data_proto,msg);
}

/**
 * @brief Print an IPv6 packet to the log
 *
 * @param err Bitmask of LOG_OPT to report this packet
 * @param p   struct pkt which encountered the error
 * @param msg string message to include in the log
 */
static void log_pkt6(int err, struct pkt *p, const char *msg)
{
	const char * type = "";
	if	   (gcfg.log_opts & err & LOG_OPT_SELF) 	type = "SELF";
	else if(gcfg.log_opts & err & LOG_OPT_DROP) 	type = "DROP";
	else if(gcfg.log_opts & err & LOG_OPT_REJECT) 	type = "REJECT";
	else if(gcfg.log_opts & err & LOG_OPT_ICMP) 	type = "ICMP";
	else return;

	/* Convert the src / dest IPv6 to strings */
	char saddr[INET6_ADDRSTRLEN],daddr[INET6_ADDRSTRLEN];
	const char * ret = inet_ntop(AF_INET6,&p->ip6->src,saddr,sizeof(saddr));
	if(!ret) {
		/* ntop got an error */
		sprintf(saddr,"ERROR:%d",errno);
	}
	ret = inet_ntop(AF_INET6,&p->ip6->dest,daddr,sizeof(daddr));
	if(!ret) {
		/* ntop got an error */
		sprintf(daddr,"ERROR:%d",errno);
	}
	/* Build final string */
	int sev = LOG_INFO;
	if(err & (LOG_OPT_DROP | LOG_OPT_REJECT)) sev = LOG_NOTICE;
	slog(sev,"%s: [v6] [%s]->[%s] (%d bytes) (proto %d) %s\n",
		type, saddr, daddr, (p->header_len + p->data_len),p->data_proto,msg);
}

static uint16_t ip_checksum(void *d, uint32_t c)
{
	uint32_t sum = 0xffff;
	uint16_t *p = d;

	while (c > 1) {
		sum += *p++;
		c -= 2;
	}

	if (c)
		sum += *((uint8_t *)p) << BIG_LITTLE(8,0);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static inline uint16_t ones_add(uint16_t a, uint16_t b)
{
	uint32_t sum = (uint16_t)~a + (uint16_t)~b;

	return ~((sum & 0xffff) + (sum >> 16));
}


static uint16_t ip4_checksum(struct ip4 *ip4, uint32_t data_len, uint8_t proto)
{
	uint32_t sum = 0;
	uint16_t *p;
	int i;

	for (i = 0, p = (uint16_t *)&ip4->src; i < 4; ++i)
		sum += *p++;
	sum += htonl(data_len) >> 16;
	sum += htonl(data_len) & 0xffff;
	sum += htons(proto);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t ip6_checksum(struct ip6 *ip6, uint32_t data_len, uint8_t proto)
{
	uint32_t sum = 0;
	uint16_t *p;
	int i;

	for (i = 0, p = ip6->src.s6_addr16; i < 16; ++i)
		sum += *p++;
	sum += htonl(data_len) >> 16;
	sum += htonl(data_len) & 0xffff;
	sum += htons(proto);

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t convert_cksum(struct ip6 *ip6, struct ip4 *ip4)
{
	uint64_t sum = 0;

	sum += ~ip4->src.s_addr;
	sum += ~ip4->dest.s_addr;
	sum += ip6->src.s6_addr32[0];
	sum += ip6->src.s6_addr32[1];
	sum += ip6->src.s6_addr32[2];
	sum += ip6->src.s6_addr32[3];
	sum += ip6->dest.s6_addr32[0];
	sum += ip6->dest.s6_addr32[1];
	sum += ip6->dest.s6_addr32[2];
	sum += ip6->dest.s6_addr32[3];

	/* Fold carry-arounds */
	if(sum > 0xffffffff) sum = (sum & 0xffffffff) + (sum >> 32);
	if(sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
	if(sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

static void host_send_icmp4(uint8_t tos, struct in_addr *src,
		struct in_addr *dest, struct tayga_icmp *icmp,
		uint8_t *data, uint32_t data_len)
{
	struct ip4_icmp header;
	struct iovec iov[2];

	TUN_SET_PROTO(&header.pi, ETH_P_IP);
	header.ip4.ver_ihl = 0x40 | (sizeof(header.ip4) >> 2);
	header.ip4.tos = tos;
	header.ip4.length = htons(sizeof(header.ip4) + sizeof(header.icmp) +
				data_len);
	header.ip4.ident = 0;
	header.ip4.flags_offset = 0;
	header.ip4.ttl = DEFAULT_TTL;
	header.ip4.proto = IPPROTO_ICMP;
	header.ip4.cksum = 0;
	header.ip4.src = *src;
	header.ip4.dest = *dest;
	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));
	header.icmp = *icmp;
	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(data, data_len),
			ip_checksum(&header.icmp, sizeof(header.icmp)));
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = data;
	iov[1].iov_len = data_len;
	if (writev(gcfg.tun_fd, iov, data_len ? 2 : 1) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
			strerror(errno));
}

static void host_send_icmp4_error(uint8_t type, uint8_t code, uint32_t word,
		struct pkt *orig)
{
	struct tayga_icmp icmp;
	uint32_t orig_len;

	/* Don't send ICMP errors in response to ICMP messages other than
	   echo request */
	if (orig->data_proto == IPPROTO_ICMP && orig->icmp->type != 8)
		return;

	orig_len = orig->header_len + orig->data_len;
	if (orig_len > IP_MSS - sizeof(struct ip4) - sizeof(struct tayga_icmp))
		orig_len = IP_MSS - sizeof(struct ip4) - sizeof(struct tayga_icmp);
	icmp.type = type;
	icmp.code = code;
	icmp.word = htonl(word);
	host_send_icmp4(0, &gcfg.local_addr4, &orig->ip4->src, &icmp,
			(uint8_t *)orig->ip4, orig_len);
}

static void host_handle_icmp4(struct pkt *p)
{
	char temp[32];
	p->data += sizeof(struct tayga_icmp);
	p->data_len -= sizeof(struct tayga_icmp);

	switch (p->icmp->type) {
	case ICMP_ECHO:
		p->icmp->type = ICMP_ECHOREPLY;
		log_pkt4(LOG_OPT_SELF,p,"Echo Request");
		host_send_icmp4(p->ip4->tos, &p->ip4->dest, &p->ip4->src,
				p->icmp, p->data, p->data_len);
		break;
	default:
		sprintf(temp,"ICMP Unknown Type %d",p->icmp->type);
		log_pkt4(LOG_OPT_SELF | LOG_OPT_DROP,p,temp);
	}
}


static void xlate_header_4to6(struct pkt *p, struct ip6 *ip6,
		int payload_length)
{
	ip6->ver_tc_fl = htonl((0x6 << 28) | (p->ip4->tos << 20));
	ip6->payload_length = htons(payload_length);
	ip6->next_header = p->data_proto == IPPROTO_ICMP ? IPPROTO_ICMPV6 : p->data_proto;
	ip6->hop_limit = p->ip4->ttl;
}

static int xlate_payload_4to6(struct pkt *p, struct ip6 *ip6, int em)
{
	uint16_t *tck;
	uint16_t cksum;

	/* Do not adjust fragment packets */
	if (p->ip4->flags_offset & htons(IP_OFFMASK))
		return ERROR_NONE;

	switch (p->data_proto) {
	/* ICMPv4 */
	case IPPROTO_ICMP:
		cksum = ip6_checksum(ip6, htons(p->ip4->length) -
						p->header_len, IPPROTO_ICMPV6);
		cksum = ones_add(p->icmp->cksum, cksum);
		if (p->icmp->type == ICMP_ECHO) {
			p->icmp->type = ICMP6_ECHO_REQUEST;
			p->icmp->cksum = ones_add(cksum, (uint16_t)~((ICMP6_ECHO_REQUEST - ICMP_ECHO)<<BIG_LITTLE(8,0)));
		} else {
			p->icmp->type = ICMP6_ECHO_REPLY;
			p->icmp->cksum = ones_add(cksum, (uint16_t)~((ICMP6_ECHO_REPLY - ICMP_ECHOREPLY)<<BIG_LITTLE(8,0)));
		}
		return ERROR_NONE;
	/* UDP */
	case IPPROTO_UDP:
		if (p->data_len < sizeof(struct udphdr)) {
			if (!em) log_pkt4(LOG_OPT_DROP,p,"Insufficient payload length for UDP Header");
			return ERROR_DROP;
		}
        tck = &((struct udphdr *)p->data)->uh_sum;
		if (!*tck) {
			/* UDP packet has no checksum, how do we deal? */
			switch(gcfg.udp_cksum_mode) {
			default:
			case UDP_CKSUM_DROP:
				/* Do not handle zero checksum packets */
				if (!em) log_pkt4(LOG_OPT_DROP,p,"Not configured to handle Zero UDP Checksum");
				return ERROR_DROP;
			case UDP_CKSUM_FWD:
				/* Ignore the lack of checksum and forward anyway */
				return ERROR_NONE;
			case UDP_CKSUM_CALC:
				/* Calculate a real UDP checksum, now */
				*tck = ones_add(ip_checksum(p->data,p->data_len), /* Body */
								ip6_checksum(ip6,p->data_len,IPPROTO_UDP));/* IP6 header */
				return ERROR_NONE;
			}
		}
		break;
	/* TCP */
	case IPPROTO_TCP:
		if (p->data_len < sizeof(struct tcphdr)) {
			if (!em) log_pkt4(LOG_OPT_DROP,p,"Insufficient payload length for TCP Header");
			return ERROR_DROP;
		}
        tck = &((struct tcphdr *)p->data)->th_sum;
		break;
	/* Any other protocol */
	default:
		return ERROR_NONE;
	}
	/* Calculate checksum adjustment */
	*tck = ones_add(*tck, ~convert_cksum(ip6, p->ip4));
	return ERROR_NONE;
}

static void xlate_4to6_data(struct pkt *p)
{
	struct ip6_data header;
	struct iovec iov[2];
	int no_frag_hdr = 0;
	uint16_t off = ntohs(p->ip4->flags_offset);
	uint32_t frag_size;
	int ret;

	frag_size = gcfg.ipv6_offlink_mtu;
	if (frag_size > gcfg.mtu)
		frag_size = gcfg.mtu;
	frag_size -= sizeof(struct ip6);

	ret = map_ip4_to_ip6(&header.ip6.dest, &p->ip4->dest);
	if (ret == ERROR_REJECT) {
		log_pkt4(LOG_OPT_REJECT,p,"Unable to map destination address");
		host_send_icmp4_error(ICMP_UNREACH, ICMP_UNREACH_HOST, 0, p);

		return;
	}
	else if(ret == ERROR_DROP) {
		log_pkt4(LOG_OPT_DROP,p,"Unable to map destination address");
		return;
	}

	ret = map_ip4_to_ip6(&header.ip6.src, &p->ip4->src);
	if (ret == ERROR_REJECT) {
		log_pkt4(LOG_OPT_REJECT,p,"Unable to map source address");
		host_send_icmp4_error(ICMP_UNREACH, ICMP_UNREACH_HOST_PROHIB, 0, p);
		return;
	}
	else if(ret == ERROR_DROP) {
		log_pkt4(LOG_OPT_DROP,p,"Unable to map source address");
		return;
	}

	/* We do not respect the DF flag for IP4 packets that are already
	   fragmented, because the IP6 fragmentation header takes an extra
	   eight bytes, which we don't have space for because the IP4 source
	   thinks the MTU is only 20 bytes smaller than the actual MTU on
	   the IP6 side.  (E.g. if the IP6 MTU is 1496, the IP4 source thinks
	   the path MTU is 1476, which means it sends fragments with 1456
	   bytes of fragmented payload.  Translating this to IP6 requires
	   40 bytes of IP6 header + 8 bytes of fragmentation header +
	   1456 bytes of payload == 1504 bytes.) */
	if ((off & (IP_OFFMASK | IP_MF)) == 0) {
		if (off & IP_DF) {
			if (gcfg.mtu - MTU_ADJ < p->header_len + p->data_len) {
				log_pkt4(LOG_OPT_ICMP,p,"Packet Too Big");
				host_send_icmp4_error(ICMP_UNREACH, ICMP_UNREACH_NEEDFRAG,
                        gcfg.mtu - MTU_ADJ, p);
				return;
			}
			no_frag_hdr = 1;
		} else if (p->data_len <= frag_size) {
			no_frag_hdr = 1;
		}
	}

	xlate_header_4to6(p, &header.ip6, p->data_len);
	--header.ip6.hop_limit;

	if (xlate_payload_4to6(p, &header.ip6,0) < 0)
		return;

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);

	if (no_frag_hdr) {
		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof(struct tun_pi) + sizeof(struct ip6);
		iov[1].iov_base = p->data;
		iov[1].iov_len = p->data_len;

		if (writev(gcfg.tun_fd, iov, 2) < 0)
			slog(LOG_WARNING, "error writing packet to tun "
					"device: %s\n", strerror(errno));
	} else {
		header.ip6_frag.ip6f_nxt = header.ip6.next_header;
		header.ip6_frag.ip6f_reserved = 0;
		header.ip6_frag.ip6f_ident = htonl(ntohs(p->ip4->ident));

		header.ip6.next_header = IPPROTO_FRAGMENT;

		iov[0].iov_base = &header;
		iov[0].iov_len = sizeof(header);

		off = (off & IP_OFFMASK) * 8;
		frag_size = (frag_size - sizeof(header.ip6_frag)) & ~7;

		while (p->data_len > 0) {
			if (p->data_len < frag_size)
				frag_size = p->data_len;

			header.ip6.payload_length =
				htons(sizeof(struct ip6_frag) + frag_size);
			header.ip6_frag.ip6f_offlg = htons(off);

			iov[1].iov_base = p->data;
			iov[1].iov_len = frag_size;

			p->data += frag_size;
			p->data_len -= frag_size;
			off += frag_size;

			if (p->data_len || (p->ip4->flags_offset &
							htons(IP_MF)))
				header.ip6_frag.ip6f_offlg |= IP6F_MORE_FRAG;

			if (writev(gcfg.tun_fd, iov, 2) < 0) {
				slog(LOG_WARNING, "error writing packet to "
						"tun device: %s\n",
						strerror(errno));
				return;
			}
		}
	}
}

static int parse_ip4(struct pkt *p)
{
	p->ip4 = (struct ip4 *)(p->data);

	/* Not long enough for IPv4 header */
	if (p->data_len < sizeof(struct ip4)) {
		log_pkt4(LOG_OPT_DROP,p,"IP Header Length");
		return ERROR_DROP;
	}

	/* Read IHL field for actual header len */
	p->header_len = (p->ip4->ver_ihl & 0x0f) * 4;

	if ((p->ip4->ver_ihl >> 4) != 4 || p->header_len < sizeof(struct ip4) ||
			p->data_len < p->header_len ||
			ntohs(p->ip4->length) < p->header_len ||
			(validate_ip4_addr(&p->ip4->src) == ERROR_DROP) ||
			(validate_ip4_addr(&p->ip4->dest) == ERROR_DROP)) {
		log_pkt4(LOG_OPT_DROP,p,"IP Header Invalid");
		return ERROR_DROP;
	}

	if (p->data_len > ntohs(p->ip4->length))
		p->data_len = ntohs(p->ip4->length);

	p->data += p->header_len;
	p->data_len -= p->header_len;
	p->data_proto = p->ip4->proto;

	if (p->data_proto == IPPROTO_ICMP) { /* ICMPv4 */
		if (p->ip4->flags_offset & htons(IP_OFFMASK | IP_MF)) {
			log_pkt4(LOG_OPT_DROP,p,"ICMP Fragmented");
			return ERROR_DROP;
		}
		if (p->data_len < sizeof(struct tayga_icmp)) {
			log_pkt4(LOG_OPT_DROP,p,"ICMP Header Length");
			return ERROR_DROP;
		}
		p->icmp = (struct tayga_icmp *)(p->data);
	} else if(p->data_proto == IPPROTO_HOPOPTS  || /* IPv6 Hop By Hop */
		      p->data_proto == IPPROTO_ROUTING  || /* IPv6 Routing Header */
		      p->data_proto == IPPROTO_FRAGMENT || /* IPv6 Fragment Header */
		      p->data_proto == IPPROTO_ICMPV6   || /* IPv6 ICMPv6 */
			  p->data_proto == IPPROTO_DSTOPTS) {  /* IPv6 Destination Options Header */
		log_pkt4(LOG_OPT_DROP,p,"IPv4 Packet with IPv6-Only Proto");
		return ERROR_DROP;
	} else {
		if ((p->ip4->flags_offset & htons(IP_MF)) &&
				(p->data_len & 0x7)) {
			log_pkt4(LOG_OPT_DROP,p,"Fragment Misalignment");
			return ERROR_DROP;
		}

		if ((uint32_t)((ntohs(p->ip4->flags_offset) & IP_OFFMASK) * 8) +
				p->data_len > UINT16_MAX) {
			log_pkt4(LOG_OPT_DROP,p,"Fragment Exceeds Max Length");
			return ERROR_DROP;
		}
	}

	return 0;
}

/* Estimates the most likely MTU of the link that the datagram in question was
 * too large to fit through, using the algorithm from RFC 1191. */
static unsigned int est_mtu(unsigned int too_big)
{
	static const unsigned int table[] = {
		65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 0
	};
	int i;

	for (i = 0; table[i]; ++i)
		if (too_big > table[i])
			return table[i];
	return 68;
}

static void xlate_4to6_icmp_error(struct pkt *p)
{
	struct ip6_error header;
	struct iovec iov[2];
	struct pkt p_em;
	uint32_t mtu;
	uint16_t em_len;
	char temp[64];

	memset(&p_em, 0, sizeof(p_em));
	p_em.data = p->data + sizeof(struct tayga_icmp);
	p_em.data_len = p->data_len - sizeof(struct tayga_icmp);

	if (p->icmp->type == ICMP_UNREACH ||
            p->icmp->type == ICMP_TIMXCEED ||
            p->icmp->type == ICMP_PARAMPROB) {
		em_len = (ntohl(p->icmp->word) >> 14) & 0x3fc;
		if (em_len) {
			if (p_em.data_len < em_len) {
				log_pkt4(LOG_OPT_DROP,p,"ICMP Option Length and Packet Too Short");
				return;
			}
			p_em.data_len = em_len;
		}
	}

	if (parse_ip4(&p_em) < 0) {
		log_pkt4(LOG_OPT_DROP,p,"Failed to parse em packet");
		return;
	}

	if (p_em.data_proto == IPPROTO_ICMP && p_em.icmp->type != ICMP_ECHO) {
		log_pkt4(LOG_OPT_DROP,p,"ICMP Error of ICMP Error");
		return;
	}

	if (sizeof(struct ip6) * 2 + sizeof(struct tayga_icmp) + p_em.data_len > MTU_MIN)
		p_em.data_len = MTU_MIN - sizeof(struct ip6) * 2 - sizeof(struct tayga_icmp);

	if (map_ip4_to_ip6(&header.ip6_em.src, &p_em.ip4->src) ||
			map_ip4_to_ip6(&header.ip6_em.dest,
					&p_em.ip4->dest)) {
		log_pkt4(LOG_OPT_DROP,p,"ICMP Failed to map em src or em dest");
		return;
	}

	xlate_header_4to6(&p_em, &header.ip6_em,
				ntohs(p_em.ip4->length) - p_em.header_len);

	switch (p->icmp->type) {
	case ICMP_UNREACH: /* Destination Unreachable */
		header.icmp.type = ICMP6_DST_UNREACH; /* Destination Unreachable */
		header.icmp.word = 0;
		switch (p->icmp->code) {
		case ICMP_UNREACH_NET: /* Network Unreachable */
			dummy();
		case ICMP_UNREACH_HOST: /* Host Unreachable */
			dummy();
		case ICMP_UNREACH_SRCFAIL: /* Source Route Failed */
			dummy();
		case ICMP_UNREACH_NET_UNKNOWN:
			dummy();
		case ICMP_UNREACH_HOST_UNKNOWN:
			dummy();
		case ICMP_UNREACH_ISOLATED:
			dummy();
		case ICMP_UNREACH_TOSNET:
			dummy();
		case ICMP_UNREACH_TOSHOST:
			header.icmp.code = ICMP6_DST_UNREACH_NOROUTE; /* No route to destination */
			break;
		case ICMP_UNREACH_PROTOCOL: /* Protocol Unreachable */
			header.icmp.type = ICMP6_PARAM_PROB;
			header.icmp.code = ICMP6_PARAMPROB_NEXTHEADER;
			header.icmp.word = htonl(6);
			break;
		case ICMP_UNREACH_PORT: /* Port Unreachable */
			header.icmp.code = ICMP6_DST_UNREACH_NOPORT; /* Port Unreachable */
			break;
		case ICMP_UNREACH_NEEDFRAG: /* Fragmentation needed and DF set */
			header.icmp.type = ICMP6_PACKET_TOO_BIG;
			header.icmp.code = 0;
			mtu = ntohl(p->icmp->word) & 0xffff;
			if (mtu < 68)
				mtu = est_mtu(ntohs(p_em.ip4->length));
			mtu += MTU_ADJ;
			/* Path MTU > our own MTU */
			if (mtu > gcfg.mtu)
				mtu = gcfg.mtu;
			/* Set MTU to 1280 to prevent generation of atomic fragments */
			if (mtu < MTU_MIN) {
				mtu = MTU_MIN;
			}
			header.icmp.word = htonl(mtu);
			break;
		case ICMP_UNREACH_NET_PROHIB:
			dummy();
		case ICMP_UNREACH_HOST_PROHIB:
			dummy();
		case ICMP_UNREACH_FILTER_PROHIB:
			dummy();
		case ICMP_UNREACH_PRECEDENCE_CUTOFF:
			header.icmp.code = ICMP6_DST_UNREACH_ADMIN; /* Administratively prohibited */
			break;
		default:
			sprintf(temp,"ICMP Unknown Dest Unreach Code %d",p->icmp->code);
			log_pkt4(LOG_OPT_DROP,p,temp);
			return;
		}
		break;
	case ICMP_TIMXCEED: /* Time Exceeded */
		header.icmp.type = ICMP6_TIME_EXCEEDED; /* Time Exceeded */
		header.icmp.code = p->icmp->code;
		header.icmp.word = 0;
		break;
	case ICMP_PARAMPROB: /* Parameter Problem */
		if (p->icmp->code != ICMP_PARAMPROB_ERRATPTR && p->icmp->code != ICMP_PARAMPROB_LENGTH) {
			log_pkt4(LOG_OPT_DROP,p,"Parameter Problem Invalid Code");
			return;
		}
		static const int32_t new_ptr_tbl[20] = {0,1,4,4,-1,-1,-1,-1,7,6,-1,-1,8,8,8,8,24,24,24,24};
		int32_t old_ptr = (ntohl(p->icmp->word) >> 24);
		if(old_ptr > 19) {
			log_pkt4(LOG_OPT_DROP,p,"Parameter Problem Invalid Pointer");
			return;
		}
		if(new_ptr_tbl[old_ptr] < 0) {
			log_pkt4(LOG_OPT_DROP,p,"Parameter Problem Not Translatable");
			return;
		}
		header.icmp.type = ICMP6_PARAM_PROB;
		header.icmp.code = ICMP6_PARAMPROB_HEADER;
		header.icmp.word = htonl(new_ptr_tbl[old_ptr]);
		break;
	default:
		sprintf(temp,"ICMP Unknown Type %d",p->icmp->type);
		log_pkt4(LOG_OPT_DROP,p,temp);
		return;
	}

	if (xlate_payload_4to6(&p_em, &header.ip6_em,1) < 0) {
		log_pkt4(LOG_OPT_DROP,p,"Unable to translate ICMP embedded payload");
		return;
	}

	if (map_ip4_to_ip6(&header.ip6.src, &p->ip4->src)) {
		log_pkt4(LOG_OPT_DROP,p,"Need to rely on fake source");
		//Fake source IP is our own IP
		header.ip6.src = gcfg.local_addr6;
	}

	if (map_ip4_to_ip6(&header.ip6.dest, &p->ip4->dest)) {
		log_pkt4(LOG_OPT_DROP,p,"Unable to map destination address");
		return;
	}

	xlate_header_4to6(p, &header.ip6,
		sizeof(header.icmp) + sizeof(header.ip6_em) + p_em.data_len);
	--header.ip6.hop_limit;

	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip6_checksum(&header.ip6,
					ntohs(header.ip6.payload_length), IPPROTO_ICMPV6),
			ones_add(ip_checksum(&header.icmp,
						sizeof(header.icmp) +
						sizeof(header.ip6_em)),
				ip_checksum(p_em.data, p_em.data_len)));

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p_em.data;
	iov[1].iov_len = p_em.data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
			strerror(errno));
}

void handle_ip4(struct pkt *p)
{
	if (parse_ip4(p) < 0) return; //error already logged
	if (p->ip4->ttl == 0 ||
			ip_checksum(p->ip4, p->header_len) ||
			p->header_len + p->data_len != ntohs(p->ip4->length)) {
		log_pkt4(LOG_OPT_DROP,p,"IP Header Invalid");
		return;
	}

	if (p->icmp && ip_checksum(p->data, p->data_len)) {
		log_pkt4(LOG_OPT_DROP,p,"ICMP Checksum is invalid");
		return;
	}

	/* Packet for ourselves*/
	if (p->ip4->dest.s_addr == gcfg.local_addr4.s_addr) {
		if (p->data_proto == IPPROTO_ICMP)
			host_handle_icmp4(p);
		else {
			log_pkt4(LOG_OPT_SELF | LOG_OPT_REJECT,p,"Self-Assigned Packet w/ Invalid Proto");
			host_send_icmp4_error(ICMP_UNREACH, ICMP_UNREACH_PROTOCOL, 0, p);
		}
	} else {
		/* Time Exceeded*/
		if (p->ip4->ttl == 1) {
			log_pkt4(LOG_OPT_ICMP,p,"Time Exceeded");
			host_send_icmp4_error(ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, 0, p);
			return;
		}
		if (p->data_proto != IPPROTO_ICMP || p->icmp->type == ICMP_ECHO ||
				p->icmp->type == ICMP_ECHOREPLY)
			xlate_4to6_data(p);
		else
			xlate_4to6_icmp_error(p);
	}
}

static void host_send_icmp6(uint8_t tc, struct in6_addr *src,
		struct in6_addr *dest, struct tayga_icmp *icmp,
		uint8_t *data, uint32_t data_len)
{
	struct ip6_icmp header;
	struct iovec iov[2];

	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);
	header.ip6.ver_tc_fl = htonl((0x6 << 28) | (tc << 20));
	header.ip6.payload_length = htons(sizeof(header.icmp) + data_len);
	header.ip6.next_header = IPPROTO_ICMPV6;
	header.ip6.hop_limit = DEFAULT_TTL;
	header.ip6.src = *src;
	header.ip6.dest = *dest;
	header.icmp = *icmp;
	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(data, data_len),
			ip_checksum(&header.icmp, sizeof(header.icmp)));
	header.icmp.cksum = ones_add(header.icmp.cksum,
			ip6_checksum(&header.ip6,
					data_len + sizeof(header.icmp), IPPROTO_ICMPV6));
	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = data;
	iov[1].iov_len = data_len;
	if (writev(gcfg.tun_fd, iov, data_len ? 2 : 1) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
			strerror(errno));
}

static void host_send_icmp6_error(uint8_t type, uint8_t code, uint32_t word,
				struct pkt *orig)
{
	struct tayga_icmp icmp;
	uint32_t orig_len;

	/* Don't send ICMP errors in response to ICMP messages other than
	   echo request */
	if (orig->data_proto == IPPROTO_ICMPV6 && orig->icmp->type != ICMP6_ECHO_REQUEST)
		return;

	orig_len = sizeof(struct ip6) + orig->header_len + orig->data_len;
	if (orig_len > MTU_MIN - sizeof(struct ip6) - sizeof(struct tayga_icmp))
		orig_len = MTU_MIN - sizeof(struct ip6) - sizeof(struct tayga_icmp);
	icmp.type = type;
	icmp.code = code;
	icmp.word = htonl(word);
	host_send_icmp6(0, &gcfg.local_addr6, &orig->ip6->src, &icmp,
			(uint8_t *)orig->ip6, orig_len);
}

static void host_handle_icmp6(struct pkt *p)
{
	char temp[32];
	p->data += sizeof(struct tayga_icmp);
	p->data_len -= sizeof(struct tayga_icmp);

	switch (p->icmp->type) {
	case ICMP6_ECHO_REQUEST:
		p->icmp->type = ICMP6_ECHO_REPLY;
		log_pkt6(LOG_OPT_SELF,p,"Echo Request");
		host_send_icmp6((ntohl(p->ip6->ver_tc_fl) >> 20) & 0xff,
				&p->ip6->dest, &p->ip6->src,
				p->icmp, p->data, p->data_len);
		break;
	default:
		sprintf(temp,"ICMP Unknown Type %d",p->icmp->type);
		log_pkt6(LOG_OPT_SELF | LOG_OPT_DROP,p,temp);
		break;
	}
}

static void xlate_header_6to4(struct pkt *p, struct ip4 *ip4,
		int payload_length)
{
	ip4->ver_ihl = 0x45;
	ip4->tos = (ntohl(p->ip6->ver_tc_fl) >> 20) & 0xff;
	ip4->length = htons(sizeof(struct ip4) + payload_length);
	/* Have an IPv6 fragment header, translate to a v4 fragment */
	if (p->ip6_frag) {
		ip4->ident = htons(ntohl(p->ip6_frag->ip6f_ident) & 0xffff);
		ip4->flags_offset =
			htons(ntohs(p->ip6_frag->ip6f_offlg) >> 3);
		if (p->ip6_frag->ip6f_offlg & IP6F_MORE_FRAG)
			ip4->flags_offset |= htons(IP_MF);
		/* Always clear DF bit */
		ip4->flags_offset &= ~htons(IP_DF);
	/* Smol packets can be fragmented downstream */
	} else if (p->header_len + payload_length <= MTU_MIN) {
		/* Need to generate a psuedo-random ident value
		 * A simple counter is not secure enough
		 * However, it doesn't actually seem to be that random in practice
		 * ref. https://datatracker.ietf.org/doc/html/rfc7739#appendix-B
		 * */
		static uint32_t ident = 0xb00b;
		if(ident & 0x1) ident ^= 0x6464beef;
		ident >>= 1;
		ip4->ident = (ident& 0xffff);
		ip4->flags_offset = 0;
	/* Packets > 1280 must kick back a Packet Too Big */
	} else {
		ip4->ident = 0;
		ip4->flags_offset = htons(IP_DF);
	}
	ip4->ttl = p->ip6->hop_limit;
	ip4->proto = p->data_proto == IPPROTO_ICMPV6 ? IPPROTO_ICMP : p->data_proto;
	ip4->cksum = 0;
}

static int xlate_payload_6to4(struct pkt *p, struct ip4 *ip4, int em)
{
	uint16_t *tck;
	uint16_t cksum;

	/* Do not adjust fragments */
	if (p->ip6_frag && (p->ip6_frag->ip6f_offlg & IP6F_OFF_MASK))
		return ERROR_NONE;

	switch (p->data_proto) {
	/* ICMPv6 */
	case IPPROTO_ICMPV6:
		cksum = ~ip6_checksum(p->ip6, htons(p->ip6->payload_length) -
							p->header_len, IPPROTO_ICMPV6);
		cksum = ones_add(p->icmp->cksum, cksum);
		if (p->icmp->type == ICMP6_ECHO_REQUEST) {
			p->icmp->type = ICMP_ECHO;
			p->icmp->cksum = ones_add(cksum, (ICMP6_ECHO_REQUEST - ICMP_ECHO)<<BIG_LITTLE(8,0));
		} else {
			p->icmp->type = ICMP_ECHOREPLY;
			p->icmp->cksum = ones_add(cksum, (ICMP6_ECHO_REPLY - ICMP_ECHOREPLY)<<BIG_LITTLE(8,0));
		}
		return ERROR_NONE;
	/* UDP */
	case IPPROTO_UDP:
		if (p->data_len < 8) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Insufficient UDP Header Length");
			return ERROR_DROP;
		}
        tck = &((struct udphdr *)p->data)->uh_sum;
		if (!*tck) {
			/* UDP packet has no checksum, how do we deal? */
			switch(gcfg.udp_cksum_mode) {
			default:
			case UDP_CKSUM_DROP:
				/* Do not handle zero checksum packets */
				if(!em) log_pkt6(LOG_OPT_DROP,p,"UDP Zero Checksum");
				return ERROR_DROP;
			case UDP_CKSUM_FWD:
				/* Ignore the lack of checksum and forward anyway */
				return ERROR_NONE;
			case UDP_CKSUM_CALC:
				/* Calculate a real UDP checksum, now */
				*tck = ones_add(ip_checksum(p->data,p->data_len), /* Body */
								ip4_checksum(ip4,p->data_len,p->data_proto));		/* IP4 psuedo-header */
				return ERROR_NONE;
			}
		}
		break;
	/* TCP */
	case IPPROTO_TCP:
		if (p->data_len < sizeof(struct tcphdr)) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Insufficient TCP Header Length");
			return ERROR_DROP;
		}
        tck = &((struct tcphdr *)p->data)->th_sum;
		break;
	/* Other */
	default:
		return ERROR_NONE;
	}
	/* Adjust checksum */
	*tck = ones_add(*tck, convert_cksum(p->ip6, ip4));
	return ERROR_NONE;
}

static void xlate_6to4_data(struct pkt *p)
{
	struct ip4_data header;
	int ret;
	struct iovec iov[2];

	ret = map_ip6_to_ip4(&header.ip4.dest, &p->ip6->dest, 0);
	if (ret == ERROR_REJECT) {
		log_pkt6(LOG_OPT_REJECT,p,"Failed to map dest addr");
		host_send_icmp6_error(ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE, 0, p);
		return;
	}
	else if (ret == ERROR_DROP){
		/* Drop packet */
		log_pkt6(LOG_OPT_DROP,p,"Failed to map dest addr");
		return;
	}

	ret = map_ip6_to_ip4(&header.ip4.src, &p->ip6->src, 1);
	if (ret == ERROR_REJECT) {
		log_pkt6(LOG_OPT_REJECT,p,"Failed to map src addr");
		host_send_icmp6_error(1, 5, 0, p);
		return;
	}
	else if (ret == ERROR_DROP){
		/* Drop packet */
		log_pkt6(LOG_OPT_DROP,p,"Failed to map src addr");
		return;
	}

	if (sizeof(struct ip6) + p->header_len + p->data_len > gcfg.mtu) {
		log_pkt6(LOG_OPT_ICMP,p,"Packet Too Big");
		host_send_icmp6_error(2, 0, gcfg.mtu, p);
		return;
	}

	xlate_header_6to4(p, &header.ip4, p->data_len);
	--header.ip4.ttl;

	if (xlate_payload_6to4(p, &header.ip4,0) < 0)
		return;

	TUN_SET_PROTO(&header.pi, ETH_P_IP);

	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p->data;
	iov[1].iov_len = p->data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
			strerror(errno));
}

static int parse_ip6(struct pkt *p,int em)
{
	uint32_t hdr_len;
	uint8_t seg_left = 0;
	uint16_t seg_ptr = sizeof(struct ip6);

	p->ip6 = (struct ip6 *)(p->data);

	if (p->data_len < sizeof(struct ip6) ||
			(ntohl(p->ip6->ver_tc_fl) >> 28) != 6 ||
			validate_ip6_addr(&p->ip6->src) ||
			validate_ip6_addr(&p->ip6->dest)) {
		/* Do not log if the src or dest was multicast */
		if(p->ip6->src.s6_addr[0] == 0xff) return ERROR_DROP;
		if(p->ip6->dest.s6_addr[0] == 0xff) return ERROR_DROP;
		if(!em) log_pkt6(LOG_OPT_DROP,p,"Failed to parse IPv6 Header");
		return ERROR_DROP;
	}

	p->data_proto = p->ip6->next_header;
	p->data += sizeof(struct ip6);
	p->data_len -= sizeof(struct ip6);

	if (p->data_len > ntohs(p->ip6->payload_length))
		p->data_len = ntohs(p->ip6->payload_length);

	while (p->data_proto == IPPROTO_IP || p->data_proto == IPPROTO_ROUTING ||
			p->data_proto == IPPROTO_DSTOPTS) {
		if (p->data_len < 2) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Extension Header Invalid Length");
			return ERROR_DROP;
		}
		hdr_len = (p->data[1] + 1) * 8;
		if (p->data_len < hdr_len) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Extension Header Invalid Length");
			return ERROR_DROP;
		}
		/* If it's a routing header, extract segments left
		 * We will drop the packet, but need to finish parsing it first
		 */
		if(p->data_proto == IPPROTO_ROUTING) seg_left = p->data[3];
		if(!seg_left) seg_ptr += hdr_len;

		/* Extract next header from extension header */
		p->data_proto = p->data[0];
		p->data += hdr_len;
		p->data_len -= hdr_len;
		p->header_len += hdr_len;
	}

	if (p->data_proto == IPPROTO_FRAGMENT) {
		if (p->ip6_frag || p->data_len < sizeof(struct ip6_frag)) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Fragment Header Invalid Length");
			return ERROR_DROP;
		}
		p->ip6_frag = (struct ip6_frag *)p->data;
		p->data_proto = p->ip6_frag->ip6f_nxt;
		p->data += sizeof(struct ip6_frag);
		p->data_len -= sizeof(struct ip6_frag);
		p->header_len += sizeof(struct ip6_frag);

		if ((p->ip6_frag->ip6f_offlg & IP6F_MORE_FRAG) &&
				(p->data_len & 0x7)) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Fragment Misaligned");
			return ERROR_DROP;
		}

		if ((uint32_t)(ntohs(p->ip6_frag->ip6f_offlg & IP6F_OFF_MASK)) +
				p->data_len > UINT16_MAX) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Fragment Reassembly exceeds max size");
			return ERROR_DROP;
		}
	}

	if (p->data_proto == IPPROTO_ICMPV6) {
		if (p->ip6_frag && (p->ip6_frag->ip6f_offlg &
					(IP6F_OFF_MASK | IP6F_MORE_FRAG))) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"Fragmented ICMP");
			return ERROR_DROP;
		}
		if (p->data_len < sizeof(struct tayga_icmp)) {
			if(!em) log_pkt6(LOG_OPT_DROP,p,"ICMP with insufficient header size");
			return ERROR_DROP;
		}
		p->icmp = (struct tayga_icmp *)(p->data);
	} else if(p->data_proto == IPPROTO_ICMP) { /* ICMPv4, which is not valid to translate */
		if(!em) log_pkt6(LOG_OPT_DROP,p,"IPv6 with IPv4-only Proto");
		return ERROR_DROP;
	}

	/* IF we got a routing header with segments left
	 * kick back a Parameter Problem pointing to the seg field
	 */
	if(seg_left) {
		seg_ptr += 4;
		if(!em) log_pkt6(LOG_OPT_REJECT,p,"Routing Header with Segments Left");
		host_send_icmp6_error(ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER, seg_ptr, p);
		return ERROR_DROP;
	}

	return ERROR_NONE;
}

static void xlate_6to4_icmp_error(struct pkt *p)
{
	struct ip4_error header;
	struct iovec iov[2];
	struct pkt p_em;
	uint32_t mtu;
	uint16_t em_len;

	memset(&p_em, 0, sizeof(p_em));
	p_em.data = p->data + sizeof(struct tayga_icmp);
	p_em.data_len = p->data_len - sizeof(struct tayga_icmp);

	if (p->icmp->type == ICMP6_DST_UNREACH || p->icmp->type == ICMP_TIME_EXCEEDED) {
		em_len = (ntohl(p->icmp->word) >> 21) & 0x7f8;
		if (em_len) {
			if (p_em.data_len < em_len) {
				log_pkt6(LOG_OPT_DROP,p,"ICMP Length Too Short");
				return;
			}
			p_em.data_len = em_len;
		}
	}

	if (parse_ip6(&p_em,1) < 0) {
		log_pkt6(LOG_OPT_DROP,p,"ICMP Error Parsing Embedded Packet");
		return;
	}

	if (p_em.data_proto == IPPROTO_ICMPV6 && p_em.icmp->type != ICMP6_ECHO_REQUEST) {
		log_pkt6(LOG_OPT_DROP,p,"ICMP Error with ICMP Error");
		return;
	}

	if (sizeof(struct ip4) * 2 + sizeof(struct tayga_icmp) + p_em.data_len > IP_MSS)
		p_em.data_len = IP_MSS - sizeof(struct ip4) * 2 -
						sizeof(struct tayga_icmp);

	switch (p->icmp->type) {
	case ICMP6_DST_UNREACH: /* Destination Unreachable */
		header.icmp.type = ICMP_UNREACH; /* Destination Unreachable */
		header.icmp.word = 0;
		switch (p->icmp->code) {
		case ICMP6_DST_UNREACH_NOROUTE: /* No route to destination */
		dummy();
		case ICMP6_DST_UNREACH_BEYONDSCOPE: /* Beyond scope of source address */
		dummy();
		case ICMP6_DST_UNREACH_ADDR: /* Address Unreachable */
			header.icmp.code = ICMP_UNREACH_HOST; /* Host Unreachable */
			break;
		case ICMP6_DST_UNREACH_ADMIN: /* Administratively prohibited */
			header.icmp.code = ICMP_HOST_ANO; /* Administratively prohibited */
			break;
		case ICMP6_DST_UNREACH_NOPORT: /* Port Unreachable */
			header.icmp.code = ICMP_UNREACH_PORT; /* Port Unreachable */
			break;
		default:
			return;
		}
		break;
	case ICMP6_PACKET_TOO_BIG: /* Packet Too Big */
		header.icmp.type = ICMP_UNREACH; /* Destination Unreachable */
		header.icmp.code = ICMP_UNREACH_NEEDFRAG; /* Fragmentation needed */
		mtu = ntohl(p->icmp->word);
		if (mtu < 68) {
			log_pkt6(LOG_OPT_DROP,p,"No MTU in Packet Too Big");
			return;
		}
		if (mtu > gcfg.mtu)
			mtu = gcfg.mtu;
		mtu -= MTU_ADJ;
		header.icmp.word = htonl(mtu);
		break;
	case ICMP6_TIME_EXCEEDED: /* Time Exceeded */
		header.icmp.type = ICMP_TIME_EXCEEDED; /* Time Exceeded */
		header.icmp.code = p->icmp->code;
		header.icmp.word = 0;
		break;
	case ICMP6_PARAM_PROB: /* Parameter Problem */
		/* Erroneous Header Field Encountered */
		if (p->icmp->code == ICMP6_PARAMPROB_HEADER) {
			static const int32_t new_ptr_tbl[8] = {0,1,-1,-1,2,2,9,8};
			int32_t old_ptr = ntohl(p->icmp->word);
			int32_t new_ptr;
			if(old_ptr > 39) {
				log_pkt6(LOG_OPT_DROP,p,"Parameter Problem Invalid Pointer");
				return;
			} else if(old_ptr > 23) {
				new_ptr = 16;
			} else if(old_ptr > 7) {
				new_ptr = 12;
			} else {
				new_ptr = new_ptr_tbl[old_ptr];
			}
			if(new_ptr < 0) {
				log_pkt6(LOG_OPT_DROP,p,"Parameter Problem Not Translatable");
				return;
			}
			header.icmp.type = ICMP_PARAMETERPROB;
			header.icmp.code = ICMP_PARAMPROB_ERRATPTR;
			header.icmp.word = (htonl(new_ptr << 24));
			break;
		/* Unrecognized Next Header Type*/
		} else if (p->icmp->code == ICMP6_PARAMPROB_NEXTHEADER) {
			header.icmp.type = ICMP_UNREACH; /* Destination Unreachable */
			header.icmp.code = ICMP_UNREACH_PROTOCOL; /* Protocol Unreachable */
			header.icmp.word = 0;
			break;
		}
		log_pkt6(LOG_OPT_DROP,p,"Parameter Problem Unknown Code");
		return;
	default:
		log_pkt6(LOG_OPT_DROP,p,"ICMP Unknown Type");
		return;
	}

	if (map_ip6_to_ip4(&header.ip4_em.src, &p_em.ip6->src, 0) ||
			map_ip6_to_ip4(&header.ip4_em.dest,
						&p_em.ip6->dest, 0)) {
		log_pkt6(LOG_OPT_DROP,p,"Failed to map em src or dest");
		return;
	}
	if(xlate_payload_6to4(&p_em, &header.ip4_em,1) < 0) {
		log_pkt6(LOG_OPT_DROP,p,"Failed to translate em payload");
		return;
	}

	xlate_header_6to4(&p_em, &header.ip4_em,
		ntohs(p_em.ip6->payload_length) - p_em.header_len);

	header.ip4_em.cksum =
		ip_checksum(&header.ip4_em, sizeof(header.ip4_em));

	//As this is an ICMP error packet, we will not further
	//send errors, so treat return of REJECT = DROP
	if (map_ip6_to_ip4(&header.ip4.src, &p->ip6->src, 0)) {
		log_pkt6(LOG_OPT_ICMP,p,"Need to rely on fake source");
		//fake source IP is our own IP
		header.ip4.src = gcfg.local_addr4;
	}

	if (map_ip6_to_ip4(&header.ip4.dest, &p->ip6->dest, 0)) {
		log_pkt6(LOG_OPT_DROP,p,"Failed to map dest");
		return;
	}

	xlate_header_6to4(p, &header.ip4, sizeof(header.icmp) +
				sizeof(header.ip4_em) + p_em.data_len);
	--header.ip4.ttl;

	header.ip4.cksum = ip_checksum(&header.ip4, sizeof(header.ip4));

	header.icmp.cksum = 0;
	header.icmp.cksum = ones_add(ip_checksum(&header.icmp,
							sizeof(header.icmp) +
							sizeof(header.ip4_em)),
				ip_checksum(p_em.data, p_em.data_len));

	TUN_SET_PROTO(&header.pi, ETH_P_IP);

	iov[0].iov_base = &header;
	iov[0].iov_len = sizeof(header);
	iov[1].iov_base = p_em.data;
	iov[1].iov_len = p_em.data_len;

	if (writev(gcfg.tun_fd, iov, 2) < 0)
		slog(LOG_WARNING, "error writing packet to tun device: %s\n",
			strerror(errno));
}

void handle_ip6(struct pkt *p)
{
	if (parse_ip6(p,0)) return;
	if (p->ip6->hop_limit == 0 ||
			p->header_len + p->data_len !=
				ntohs(p->ip6->payload_length)) {
		log_pkt6(LOG_OPT_DROP,p,"Insufficient Length");
		return;
	}

	if (p->icmp && ones_add(ip_checksum(p->data, p->data_len),
				ip6_checksum(p->ip6, p->data_len, IPPROTO_ICMPV6))) {
		log_pkt6(LOG_OPT_DROP,p,"ICMP Invalid Checksum");
		return;
	}

	if (IN6_ARE_ADDR_EQUAL(&p->ip6->dest, &gcfg.local_addr6)) {
		if (p->data_proto == IPPROTO_ICMPV6)
			host_handle_icmp6(p);
		else {
			log_pkt6(LOG_OPT_SELF | LOG_OPT_REJECT,p,"Unknown protocol to self");
			host_send_icmp6_error(ICMP6_PARAM_PROB, ICMP6_PARAMPROB_NEXTHEADER, 6, p);
		}
	} else {
		if (p->ip6->hop_limit == 1) {
			log_pkt6(LOG_OPT_ICMP,p,"Time Exceeded");
			host_send_icmp6_error(ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0, p);
			return;
		}

		if (p->data_proto != IPPROTO_ICMPV6 || p->icmp->type == ICMP6_ECHO_REQUEST ||
				p->icmp->type == ICMP6_ECHO_REPLY)
			xlate_6to4_data(p);
		else
			xlate_6to4_icmp_error(p);
	}
}
