#include "pcap-test.h"

void print_mac(const uint8_t* mac) {
    for (int i =0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]); // ex) 1 byte -> FF
        if (i != ETHER_ADDR_LEN -1)
            printf(":");
    }
}

void print_payload(const u_char* payload, int len) {
    int max_len = len < 20 ? len : 20;
    for (int i=0; i< max_len; i++) {
        printf("%02x ", payload[i]);
    }
}
void parse_packet(const u_char* packet, int caplen) {
    //Ethernet header parsing
    const struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

    printf("Ethernet SMAC : ");
    print_mac(eth_hdr->ether_shost);
    printf("\n");

    printf("Ethernet DMAC : ");
    print_mac(eth_hdr->ether_dhost);
    printf("\n");

    //IP
    const struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

    char src_ip[INET_ADDRSTRLEN]; //16
    char dst_ip[INET_ADDRSTRLEN]; //16
    //ipv4 type(000.000.000.000)
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));
    printf("IP src: %s\n", src_ip);
    printf("IP dst: %s\n", dst_ip);

    //TCP
    int ip_hdr_len = ip_hdr->ip_hl*4;
    //u_char*로 바이트 단위 캐스팅
    const struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((u_char*)ip_hdr + ip_hdr_len);

    printf("TCP src port: %u\n", ntohs(tcp_hdr->th_sport));
    printf("TCP dst port: %u\n", ntohs(tcp_hdr->th_dport));

    //Payload
    int tcp_hdr_len = tcp_hdr->th_off * 4;
    //u_char*로 바이트 단위 캐스팅
    const u_char* payload = (u_char*)tcp_hdr + tcp_hdr_len;
    int payload_len = caplen - (sizeof(struct libnet_ethernet_hdr) + ip_hdr_len + tcp_hdr_len);
    printf("Payload: ");
    print_payload(payload, payload_len);
    printf("\n\n");
}
