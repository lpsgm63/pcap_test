#ifndef __FRAME_H
#define __FRAME_H 1

#define ETH_LEN 6
#define IP_LEN 4
#define TYPE_TCP 6
#define TYPE_IPV4 0x0800

typedef struct _ether_addr{
	uint8_t addr[ETH_LEN];
}ether_addr;

typedef struct _ip_addr{
	uint8_t addr[IP_LEN];
}ip_addr;

typedef struct _ether_header{
	ether_addr des;
	ether_addr src;
	uint16_t type;
}ether_header;

typedef struct _ip_header {
	uint8_t header_length:4; // 4비트를 할당할때 최하위 비트를 먼저 가져기 때문에 header_length가 먼저 온다.
	uint8_t version:4;
	uint8_t tos;
	uint16_t length;
	uint16_t fragment;
	uint16_t fragment_flag:3;
	uint16_t fragment_offset:13;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	ip_addr src;
	ip_addr des;
}ip_header; 

typedef struct _tcp_header{
	uint16_t srcport;
	uint16_t desport;
	uint8_t sequence_number[4];
	uint8_t ack_number[4];
	uint8_t reserved_part1:4;
	uint8_t header_length:4;
	uint8_t FIN:1;
	uint8_t SYN:1;
	uint8_t RST:1;
	uint8_t PSH:1;
	uint8_t ACK:1;
	uint8_t URG:1;
	uint8_t reserved_part2:2;
	uint16_t window_size;
	uint16_t checksum;
}tcp_header;

#endif
