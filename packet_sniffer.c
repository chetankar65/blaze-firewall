#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>      
#include <netinet/tcp.h>     
#include <arpa/inet.h>      

void my_packet_handler(
    __u_char *args,
    const struct pcap_pkthdr *header,
    const __u_char *packet
);

void print_packet_info(const __u_char *packet, struct pcap_pkthdr packet_header) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header*) packet;

    // Check Ethernet type
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("Protocol: IP\n");

        // Get the IP header (Ethernet header is 14 bytes)
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Print source and destination IP addresses
        char src_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dest_ip);

        // Check if the protocol is TCP
        if (ip_header->ip_p == IPPROTO_TCP) {
            printf("Protocol: TCP\n");

            // Get the TCP header (IP header size is variable, check ip_hl field)
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

            // Print source and destination ports
            printf("Source Port: %d\n", ntohs(tcp_header->source));
            printf("Destination Port: %d\n", ntohs(tcp_header->dest));
        } else {
            printf("Non-TCP Protocol: %d\n", ip_header->ip_p);
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("Protocol: ARP\n");
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Protocol: Reverse ARP\n");
    } else {
        printf("Unknown Protocol: 0x%04x\n", ntohs(eth_header->ether_type));
    }
}

void my_packet_handler(
    __u_char *args,
    const struct pcap_pkthdr *packet_header,
    const __u_char *packet_body
)
{
    print_packet_info(packet_body, *packet_header);
    return;
}

int main(int argc, char **argv) {
    char *device = NULL;
    char ip[13];
    char subnet_mask[13];
    pcap_if_t *interface_list; // stores every network interface on device
    bpf_u_int32 ip_raw; /* IP address as integer */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as integer */
    int lookup_return_code;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    struct in_addr address; /* Used for both ip & subnet */

    // find a device
   if (pcap_findalldevs(&interface_list, error_buffer) == PCAP_ERROR) {
        printf("Could not list all interfaces\n");
        return 1;
   }

    pcap_if_t *interface;
    for (interface = interface_list; interface != NULL; interface = interface->next) {
        if (!device) {
            device = interface->name;
            break;
        }
        //printf("Name %s (%s)\n", interface->name, interface->description);
    }

    /* Get device info */
    lookup_return_code = pcap_lookupnet(
        device,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );
    if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }

    /* Get ip in human readable form */
    address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));
    if (ip == NULL) {
        perror("inet_ntoa"); /* print error */
        return 1;
    }
    
    /* Get subnet mask in human readable form */
    address.s_addr = subnet_mask_raw;
    strcpy(subnet_mask, inet_ntoa(address));
    if (subnet_mask == NULL) {
        perror("inet_ntoa");
        return 1;
    }

    printf("IP address: %s\n", ip);
    printf("Subnet mask: %s\n", subnet_mask);

    // define all variables used in packet capture
    const __u_char *packet;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */
    pcap_t *handle; /// opening a network device for live packet capture

    // start live packet capture
    handle = pcap_open_live(
        device,
        BUFSIZ,
        packet_count_limit,
        timeout_limit,
        error_buffer
    );

    if (handle == NULL) {
        printf("Error opening device %s: %s\n", device, error_buffer);
        pcap_freealldevs(interface_list);
        return 1;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);

    /// print packet info
    print_packet_info(packet, packet_header);

    pcap_freealldevs(interface_list);
    pcap_close(handle);
    return 0;
}