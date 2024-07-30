#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <time.h>

void start_capture(const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    int ip_header_length;
    int tcp_header_length;
    int total_headers_size, data_length;
    u_char *data;

    time_t now;
    struct tm *time_info;
    char logging_time[80];

    time(&now);
    time_info = localtime(&now);
    strftime(logging_time, sizeof(logging_time), "%Y-%m-%d %H:%M:%S", time_info);


    eth_header = (struct ether_header *)pkt_data;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(pkt_data + sizeof(struct ether_header));
        ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header_length);
            tcp_header_length = tcp_header->th_off * 4;

            if (pkt_header->len < sizeof(struct ether_header) + ip_header_length + tcp_header_length) {
                fprintf(stderr, "Invalid packet size\n");
                return;
            }

            total_headers_size = sizeof(struct ether_header) + ip_header_length + tcp_header_length;
            data_length = pkt_header->len - total_headers_size;
            data = (u_char *)pkt_data + total_headers_size;

            printf("------------%s------------\n", logging_time);

	    printf("\tSRC MAC == %s \n", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
	    printf("\tSRC IP == %s \n", inet_ntoa(ip_header->ip_src));
            printf("\tSRC PORT == %d \n\n", ntohs(tcp_header->th_sport));          

	    printf("\tDST MAC == %s \n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
            printf("\tDST IP == %s \n", inet_ntoa(ip_header->ip_dst));
            printf("\tDST PORT == %d \n\n", ntohs(tcp_header->th_dport));
	    
            printf("\tDATA (up to 20 bytes)\n\t");

	    for (int i = 0; i < data_length && i < 20; i++) {
                printf("%02x ", data[i]);

		if(i == 9)
			printf("\n\t");
            }
            printf("\n\n");
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Syntax: %s <interface>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *pkt_data;
    struct pcap_pkthdr pkt_header;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    while (1) {
        pkt_data = pcap_next(handle, &pkt_header);
        if (pkt_data != NULL) {
            start_capture(&pkt_header, pkt_data);
        }
    }

    pcap_close(handle);
    return 0;
}

