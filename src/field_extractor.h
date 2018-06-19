/*-
 * field_extractor.h - Extract L2/L3/L4 and NSH header fields
 *
 * Copyright (c) 2018, Jeff Rybczynski <jeff.rybczynski@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __FIELD_EXTRACTOR_H__
#define __FIELD_EXTRACTOR_H__

#include <netinet/in.h>
#include <net/if.h>

/*
 * L2/Ethernet Header
 */
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

/* Ethernet header */
struct fe_ethernet {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    uint16_t outter_ether_type;                     /* IP? ARP? RARP? etc */
    uint16_t tpid;                     /* IP? ARP? RARP? etc */
    uint16_t inner_ether_type;                     /* IP? ARP? RARP? etc */
} __attribute__((packed));

static const inline uint16_t GET_ETHERTYPE (const uint8_t *eth_hdr) {
    uint16_t ethertype = ntohs(((struct fe_ethernet *)(eth_hdr))->outter_ether_type);

    switch (ethertype) {
        case ETHERTYPE_VLAN:
            ethertype = ntohs(((struct fe_ethernet *)(eth_hdr))->inner_ether_type);
            break;
        case ETHERTYPE_IPV4:
        case ETHERTYPE_IPV6:
        default:
            break;
    }
    return (ethertype);
}

static const inline uint8_t *GET_L3_START (const uint8_t *eth_hdr) {
    uint16_t ethertype = ntohs(((struct fe_ethernet *)(eth_hdr))->outter_ether_type);
    uint32_t ethersize = SIZE_ETHERNET;

    switch (ethertype) {
        case ETHERTYPE_VLAN:
            ethersize += 4;
            break;
        case ETHERTYPE_IPV4:
        case ETHERTYPE_IPV6:
        default:
            break;
    }
    return (eth_hdr + ethersize);
}

/*
 * L3/IP Header
 */
/* IP header */
struct fe_ip {
    uint8_t  ip_vhl;                 /* version << 4 | header length >> 2 */
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
} __attribute__((packed));
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl & 0xf0) >> 4)

static const inline uint8_t GET_IP_VER (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (IP_V(ip));
}

static const inline uint8_t GET_IP_HL (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (IP_HL(ip) * 4);
}

static const inline uint16_t GET_IP_TOTLEN (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (ntohs(ip->ip_len));
}

static const inline uint8_t GET_IPPROTO (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (ip->ip_p);
}

static const inline struct in_addr GET_IP_SRCIP (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (ip->ip_src);
}

static const inline struct in_addr GET_IP_DSTIP (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (ip->ip_dst);
}

static const inline uint8_t *GET_L4_START (const uint8_t *ip_hdr) {
    struct fe_ip *ip = (struct fe_ip *)ip_hdr;
    return (ip_hdr + (IP_HL(ip) * 4));
}

/*
 * L4/TCP/UDP Header
 */
/* TCP header */
typedef u_int tcp_seq;

struct fe_tcp {
    uint16_t th_sport;               /* source port */
    uint16_t th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    uint8_t  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t th_win;                 /* window */
    uint16_t th_sum;                 /* checksum */
    uint16_t th_urp;                 /* urgent pointer */
} __attribute__((packed));

static const inline uint8_t GET_TCP_HDR_LEN (const uint8_t *tcp_hdr) {
    struct fe_tcp *tcp = (struct fe_tcp *)tcp_hdr;
    return (TH_OFF(tcp) * 4);
}

static const inline uint16_t GET_TCP_SRCPORT (const uint8_t *tcp_hdr) {
    struct fe_tcp *tcp = (struct fe_tcp *)tcp_hdr;
    return (ntohs(tcp->th_sport));
}

static const inline uint16_t GET_TCP_DSTPORT (const uint8_t *tcp_hdr) {
    struct fe_tcp *tcp = (struct fe_tcp *)tcp_hdr;
    return (ntohs(tcp->th_dport));
}

static const inline uint8_t *GET_TCP_PAYLOAD (const uint8_t *tcp_hdr) {
    struct fe_tcp *tcp = (struct fe_tcp *)tcp_hdr;
    return (tcp_hdr + (TH_OFF(tcp) * 4));
}

#define UDP_HDR_LEN 8

struct fe_udp {
    uint16_t uh_sport;               /* source port */
    uint16_t uh_dport;               /* destination port */
    uint16_t uh_len;                 /* datagram length */
    uint16_t uh_sum;                 /* checksum */
} __attribute__((packed));

static const inline uint8_t GET_UDP_HDR_LEN (const uint8_t *udp_hdr) {
    //struct fe_udp *udp = (struct fe_udp *)udp_hdr;
    return (UDP_HDR_LEN);
}

static const inline uint16_t GET_UDP_SRCPORT (const uint8_t *udp_hdr) {
    struct fe_udp *udp = (struct fe_udp *)udp_hdr;
    return (ntohs(udp->uh_sport));
}

static const inline uint16_t GET_UDP_DSTPORT (const uint8_t *udp_hdr) {
    struct fe_udp *udp = (struct fe_udp *)udp_hdr;
    return (ntohs(udp->uh_dport));
}

static const inline uint16_t GET_UDP_DGRAM_LENGTH (const uint8_t *udp_hdr) {
    struct fe_udp *udp = (struct fe_udp *)udp_hdr;
    return (ntohs(udp->uh_len));
}

static const inline uint8_t *GET_UDP_PAYLOAD (const uint8_t *udp_hdr) {
    //struct fe_udp *udp = (struct fe_udp *)udp_hdr;
    return (udp_hdr + UDP_HDR_LEN);
}

/*
 * GRE header
 */
struct fe_gre_base {
    uint16_t flags;
#define GRE_TUNNEL_CSUM 0x01
#define GRE_TUNNEL_KEY 0x04
#define GRE_TUNNEL_SEQ 0x08
    uint16_t next_prot;
}__attribute__((packed));

#define GRE_BASE_HEADER_SIZE 4

struct fe_gre {
    struct fe_gre_base fixed_hdr;
    uint16_t checksum;
    uint16_t res;
    uint32_t key;
    uint32_t seq;
}__attribute__((packed));

static inline uint16_t GET_GRE_HDR_LENGTH (const uint8_t *gre_hdr) {
    struct fe_gre *gre = (struct fe_gre *)gre_hdr;
    uint16_t length = GRE_BASE_HEADER_SIZE;
    if (gre->fixed_hdr.flags & GRE_TUNNEL_CSUM)
	length += 4;
    if (gre->fixed_hdr.flags & GRE_TUNNEL_KEY)
	length += 4;
    if (gre->fixed_hdr.flags & GRE_TUNNEL_SEQ)
	length += 4;
    return (length);
}

/*
 * NSH header
 */
struct fe_nsh_md1_ctx {
    uint32_t context[4];
}__attribute__((packed));

struct fe_nsh_md2_ctx {
    uint16_t class;
    uint8_t type;
    uint8_t len;
    uint8_t value[];
}__attribute__((packed));

struct fe_nsh {
    uint16_t ver_flags_ttl_len;
#define NSH_VER_MASK 0xc000
#define NSH_VER_SHIFT 14
#define NSH_FLAGS_MASK 0x3000
#define NSH_FLAGS_SHIFT 12
#define NSH_TTL_MASK 0x0fc0
#define NSH_TTL_SHIFT 6
#define NSH_LEN_MASK 0x003f
#define NSH_LEN_SHIFT 0
    uint8_t md_type;
#define NSH_MDTYPE_MASK 0x0f
#define NSH_MDTYPE_SHIFT 0
    uint8_t next_prot;
    uint32_t svr_path;
#define NSH_SPI_MASK 0xffffff00
#define NSH_SPI_SHIFT 8
#define NSH_SI_MASK 0x000000ff
#define NSH_SI_SHIFT 0
    union {
	struct fe_nsh_md1_ctx md1;
	struct fe_nsh_md2_ctx md2;
    };
}__attribute__((packed));

static const inline uint16_t GET_NSH_HDR_LENGTH (const uint8_t *nsh_hdr) {
    struct fe_nsh *nsh = (struct fe_nsh *)nsh_hdr;
    return ((ntohs(nsh->ver_flags_ttl_len) & NSH_LEN_MASK) >>
	    NSH_LEN_SHIFT) << 2;
}

#endif
