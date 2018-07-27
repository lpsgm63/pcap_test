#ifndef __FRAME_H
#define __FRAME_H 1

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
	u_int8_t header_length:4; // 4비트를 할당할때 최하위 비트를 먼저 가져기 때문에 header_length가 먼저 온다.
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
	u_int8_t sequence_number[4];
	u_int8_t ack_number[4];
	u_int16_t reserved_part1:4;
	u_int16_t header_length:4;
	u_int16_t reserved_part2:2;
	u_int16_t control_flag:6;
	u_int16_t window_size;
	u_int16_t checksum;
}tcp_header;

void usage();
void analysis(const unsigned char *, int);
int print_ether(ether_header *);
int print_ip(ip_header *);
int print_tcp(tcp_header *);

#endif
