/**
pcap을 이용하여 송수신 되는 packet의eth.smac, eth.dmac/ ip.sip, ip.dip/ tcp.sport, tcp.dport / data
**/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
//#include <net/ethernet.h> //tcp 프로토콜 타입 정의
//#include "frame.h"

#define ETH_LEN 6
#define IP_LEN 4
#define TYPE_TCP 6
#define TYPE_IPV4 0x0800

typedef struct _ether_addr{
	u_int8_t addr[ETH_LEN];
}ether_addr;

typedef struct _ip_addr{
	u_int8_t addr[IP_LEN];
}ip_addr;

typedef struct _ether_header{
	ether_addr des;
	ether_addr src;
	u_int16_t type;
}ether_header;

typedef struct _ip_header {
	u_int8_t header_length:4;
	u_int8_t version:4;
	u_int8_t tos;
	u_int16_t length;
	u_int16_t fragment;
	u_int16_t fragment_flag:3;
	u_int16_t fragment_offset:13;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t checksum;
	ip_addr src;
	ip_addr des;
}ip_header; 

typedef struct _tcp_header{
	u_int16_t srcport;
	u_int16_t desport;
	u_int32_t sequence_number;
	u_int32_t ack_number;
	u_int16_t header_length:4;
	u_int16_t reserved:6;
	u_int16_t control_flag:6;
	u_int16_t window_size;
	u_int16_t checksum;
}tcp_header;

void usage();
void analysis(const unsigned char *, int);
int print_ether(ether_header *);
int print_ip(ip_header *);
int print_tcp(tcp_header *);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage(); return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
	else if (res == -1 || res == -2) break;
	printf("------------------------------------------------\n");
	analysis(packet,header->caplen);
    //printf("%u bytes captured\n", header->caplen);
	printf("------------------------------------------------\n");
  }

  pcap_close(handle);
  return 0;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void analysis(const unsigned char *packet, int length){

	int offset = 0;
	int total_length = 0;
	
	offset = print_ether((ether_header *)packet);
	if(offset == -1) return ;
	packet = packet + offset;
	total_length += offset;

	offset = print_ip((ip_header *)packet);
	if(offset == -1) return ;
	packet = packet + offset;
	total_length += offset;

	offset = print_tcp((tcp_header *)packet);
	packet = packet + offset;
	total_length += offset;
	
	
	printf("Data : "); 
	for(int i = total_length;i<length;i++){
		printf("%02x ", packet[i]);
	}
	printf("%02x\n", packet[length]);
}

int print_ether(ether_header *ether){
	if(ntohs(ether->type) != TYPE_IPV4) return -1;
	printf("Destination MAC Address : ");
	for (int i=0; i<5; i++)
		printf("%02x : ",ether->des.addr[i]);
	printf("%02x\n",ether->des.addr[5]);
	printf("Source MAC Address : ");
	for (int i=0; i<5; i++)
		printf("%02x : ",ether->src.addr[i]);
	printf("%02x\n",ether->src.addr[5]);
	return sizeof(ether_header);
}

int print_ip(ip_header *ip){
	if(ip->protocol != TYPE_TCP) return -1;
	printf("Destination IP Address :");
	for (int i=0; i<3 ;i++)
		printf("%d : ",ip->des.addr[i]); 
	printf("%d\n",ip->des.addr[3]);
	printf("Source IP Address :");
	for (int i=0; i<3 ;i++)
		printf("%d : ",ip->src.addr[i]);
	printf("%d\n",ip->src.addr[3]);
	return ip->header_length * 4;
}


int print_tcp(tcp_header *tcp){
	printf("Destination TCP Port : %d\n",ntohs(tcp->desport));
	printf("Source TCP Port : %d\n",ntohs(tcp->srcport));
	return tcp->header_length;
}
