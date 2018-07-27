/**
pcap을 이용하여 송수신 되는 packet의eth.smac, eth.dmac/ ip.sip, ip.dip/ tcp.sport, tcp.dport / data 출력
**/

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "frame.h"
//#include <net/ethernet.h> //tcp 프로토콜 타입 정의

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
	int i = 0;
	
	offset = print_ether((ether_header *)packet);
	if(offset == -1) return ;
	packet = packet + offset;
	total_length += offset;

	offset = print_ip((ip_header *)packet);
	if(offset == -1) return ;
	packet = packet + offset;
	total_length += offset;

	offset = print_tcp((tcp_header *)packet);
	packet += offset;
	total_length += offset;
	if(total_length != length){
		printf("Data : "); 
		for(i = 0; i < length-total_length; i++){
			printf("%02x ", packet[i]);
		}
		printf("%02x\n", packet[i]);
	}
}

int print_ether(ether_header *ether){
	if(ntohs(ether->type) != TYPE_IPV4) return -1;
	printf("Destination MAC Address : ");
	for (int i=0; i<ETH_LEN-1; i++)
		printf("%02x : ",ether->des.addr[i]);
	printf("%02x\n",ether->des.addr[ETH_LEN-1]);
	printf("Source MAC Address : ");
	for (int i=0; i<ETH_LEN-1; i++)
		printf("%02x : ",ether->src.addr[i]);
	printf("%02x\n",ether->src.addr[ETH_LEN-1]);
	return sizeof(ether_header);
}

int print_ip(ip_header *ip){
	if(ip->protocol != TYPE_TCP) return -1;
	printf("Destination IP Address :");
	for (int i=0; i<IP_LEN-1 ;i++)
		printf("%d : ",ip->des.addr[i]); 
	printf("%d\n",ip->des.addr[IP_LEN-1]);
	printf("Source IP Address :");
	for (int i=0; i<IP_LEN-1 ;i++)
		printf("%d : ",ip->src.addr[i]);
	printf("%d\n",ip->src.addr[IP_LEN-1]);
	return ip->header_length * 4;
}


int print_tcp(tcp_header *tcp){
	printf("Destination TCP Port : %d\n",ntohs(tcp->desport));
	printf("Source TCP Port : %d\n",ntohs(tcp->srcport));
	return tcp->header_length * 4;
}
