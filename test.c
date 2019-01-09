//
//  offline-filter.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2017/01/19.
//
//  Filter a offline file using filter.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#define __FAVOR_BSD
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <netinet/ether.h>
#endif /* if linux */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAC_ADDRSTRLEN 2*6+5+1
#define STR_BUF 16
static const char *mac_ntoa(u_int8_t *d);
static const char *ip_ntoa(void *i);

static void dump_ethernet(u_int32_t length, const u_char *content);
static void dump_ip(u_int32_t length, const u_char *content);
static void dump_tcp(u_int32_t length, const u_char *content);
static void dump_udp(u_int32_t length, const u_char *content);
static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);

int main(int argc, const char * argv[]) {

    const char *filter = "";
    if(argc == 2) {
        filter = argv[1];
    }//end if

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *filename = "saved.pcap";

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }//end if
    printf("Open: %s\n", filename);

    //compile filter
    struct bpf_program fcode;
    if(-1 == pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN)) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(1);
    }//end if
	
    //set filter
    if(-1 == pcap_setfilter(handle, &fcode)) {
        fprintf(stderr, "pcap_pcap_setfilter(): %s\n", pcap_geterr(handle));
        pcap_freecode(&fcode);
        pcap_close(handle);
        exit(1);
	}//end if
	
    if(strlen(filter) != 0) {
        printf("Filter: %s\n", filter);
    }//end if
    
    int total_amount = 0;
    int total_bytes = 0;
	
    while(1) {
        struct pcap_pkthdr *header = NULL;
        const u_char *content = NULL;
        int ret = 
        pcap_next_ex(handle, &header, &content);
        if(ret == 1) {
            if(pcap_offline_filter(&fcode, header, content) != 0) {  
                total_amount++;
                total_bytes += header->caplen;
				fprintf(stderr,"\rtotal_amount:%d\n",total_amount);
 				//pcap_loop(handle, 0, pcap_callback, NULL);
				pcap_callback(NULL,header,content);
            }//end if match
        }//end if success
        else if(ret == 0) {
            printf("Timeout\n");
        }//end if timeout
        else if(ret == -1) {
            fprintf(stderr, "pcap_next_ex(): %s\n", pcap_geterr(handle));
        }//end if fail
        else if(ret == -2) {
            printf("No more packet from file\n");
            break;
        }//end if read no more packet
    }//end while

    //result
    printf("Read: %d, byte: %d bytes\n", total_amount, total_bytes);

    //free
    pcap_freecode(&fcode);
    pcap_close(handle);
    
    return 0;
}//end main

static const char *mac_ntoa(u_int8_t *d) {
    static char mac[STR_BUF][MAC_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MAC_ADDRSTRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}//end mac_ntoa

static const char *ip_ntoa(void *i) {
    static char ip[STR_BUF][INET_ADDRSTRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);
    
    memset(ip[which], 0, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, i, ip[which], sizeof(ip[which]));
    
    return ip[which];
}//end ip_ntoa

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    struct tm *ltime;
    char timestr[50];
    time_t local_tv_sec;
    
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y/%m/%d %H:%M:%S", ltime);
    
    printf("No. %d\n", ++d);
    
    //print header
    printf("\tTime: %s.\n", timestr);
    printf("\tLength: %d bytes\n", header->len);
    printf("\tCapture length: %d bytes\n", header->caplen);
    
    //dump ethernet
    dump_ethernet(header->caplen, content);
    
    printf("\n");
}//end pcap_callback

static void dump_ethernet(u_int32_t length, const u_char *content) {
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;
    
    struct ether_header *ethernet = (struct ether_header *)content;

    //copy header
    snprintf(dst_mac, sizeof(dst_mac), "%s", mac_ntoa(ethernet->ether_dhost));
    snprintf(src_mac, sizeof(src_mac), "%s", mac_ntoa(ethernet->ether_shost));
    type = ntohs(ethernet->ether_type);

	if(type==ETHERTYPE_IP)
		dump_ip(length, content);

	
}//end dump_ethernet

static void dump_ip(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);

	u_char protocol = ip->ip_p;
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    //copy ip address
    snprintf(src_ip, sizeof(src_ip), "%s", ip_ntoa(&ip->ip_src));
    snprintf(dst_ip, sizeof(dst_ip), "%s", ip_ntoa(&ip->ip_dst));

    printf("Protocol: IP\n");	

    printf("+------------+------------+-------------------------+\n");
    printf("| Source IP Address:                 %15s|\n", src_ip);
    printf("+---------------------------------------------------+\n");
    printf("| Destination IP Address:            %15s|\n", dst_ip);
    printf("+---------------------------------------------------+\n");
	
	if(protocol==IPPROTO_UDP)
    	dump_udp(length, content);
	else if(protocol==IPPROTO_TCP)
		dump_tcp(length, content);

}//end dump_ip

static void dump_tcp(u_int32_t length, const u_char *content) 
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));	

	u_int16_t source_port = ntohs(tcp->th_sport);
	u_int16_t destination_port = ntohs(tcp->th_dport);
	
 	//print	
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
	printf("+-------------------------+-------------------------+\n");	
	
	
}
static void dump_udp(u_int32_t length, const u_char *content)
{
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
	struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t source_port = ntohs(udp->uh_sport);
	u_int16_t destination_port = ntohs(udp->uh_dport);	
	
    printf("Protocol: UDP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
	printf("+-------------------------+-------------------------+\n");	
}

