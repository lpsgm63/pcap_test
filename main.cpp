/**
pcap을 이용하여 송수신 되는 packet의eth.smac, eth.dmac/ ip.sip, ip.dip/ tcp.sport, tcp.dport / data 출력
**/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "frame.h"
//#include <net/ethernet.h> //tcp 프로토콜 타입 정의

void analysis(const unsigned char *, int);
void usage();
void print_tcp(tcp_header *);
int print(uint8_t *, uint8_t *, uint8_t);
	
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
	analysis(packet,header->caplen);
  }

  pcap_close(handle);
  return 0;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void analysis(const unsigned char *packet, int length){

	int total_length = 0;
	int i = 0;
	int offset;

	ether_header *ether;
	ip_header *ip;
	tcp_header *tcp;


	ether = (ether_header *)packet;
	if(ntohs(ether->type) != TYPE_IPV4) return;
	offset = sizeof(ether_header);
	total_length += offset;
	packet += offset;

	ip = (ip_header *)packet;
	if(ip->protocol != TYPE_TCP) return;
	offset = ip->header_length * 4;
	total_length += offset;
	packet +=offset;

	tcp = (tcp_header *)packet;
	offset = tcp->header_length * 4;
	total_length += offset;
	packet += offset;

	print(ether->des.addr,ether->src.addr,ETH_LEN);
	print(ip->des.addr,ip->src.addr,IP_LEN);
	print_tcp(tcp);

	if(tcp->PSH){
		printf("Data : "); 
		for(i = 0; i < 16; i++){
			printf("%02x ", packet[i]);
		}
	}
	printf("------------------------------------------------\n");
}

int print(uint8_t *des, uint8_t *src, uint8_t len){
	int i;
	printf("Destination : ");
	for (i = 0; i<len-1; i++)
		printf("%02x : ", des[i]); 
	printf("%02x\n",des[i]);
	printf("Source : ");
	for (i = 0; i<len-1; i++)
		printf("%02x : ", src[i]); 
	printf("%02x\n",src[i]);
}

void print_tcp(tcp_header *tcp){
	printf("Destination : %d\n",ntohs(tcp->desport));
	printf("Source : %d\n",ntohs(tcp->srcport));
}
