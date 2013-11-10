#include "mtu.h"
#include "ip.h"

typedef struct udp_pkt_t {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
    uint8_t data[MAX_MTU-7*4]; //remaining size after IP header (no options)
}udp_pkt_t;


/* Only used to calculate checksums*/
typedef struct udp_psuedo_header_t{
    uint8_t source_ip[4];
    uint8_t dest_ip[4];
    uint8_t zero; //padding
    uint8_t protocol; //IP protocol
    uint16_t udp_length; //length of datagram
    udp_pkt_t pkt; //the packet we are interested in. 
}udp_pseudo_header;

