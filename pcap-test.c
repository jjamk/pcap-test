#include "pcap-test.h"

//Error
void usage() {
	printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	//pcap open Error
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		//packet receive(header=size)
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        // Ethernet header
        const struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800) { //IPv4
            continue;
        }

        // IP header
        const struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        if (ip_hdr->ip_p != 6) { //tcp
            continue;
        }
        //printf("%u bytes captured\n", header->caplen); //don't use len, use caplen
        parse_packet(packet, header->caplen);
	}

	pcap_close(pcap);
}
