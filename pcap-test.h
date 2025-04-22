#include <netinet/in.h>
#include <sys/types.h>
#include <stdio.h>
#include <pcap.h>
#include <stdbool.h>
#include <string.h>

#define ETHER_ADDR_LEN 6 // 48bit

void parse_packet(const u_char* packet, int caplen);
void print_mac(const uint8_t* mac);

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* 0~5 byte: destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* 6~11 byte: source ethernet address */
    u_int16_t ether_type;                 /* 12~13 byte: protocol */
};


struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* (4bit): header length */
            ip_v:4;         /* (4bit):version */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};


struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
        th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};// PCAP_TEST_H
