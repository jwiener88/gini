#include "mtu.h"
#include "ip.h"

//useful reference: http://medusa.sdsu.edu/network/CS576/Lectures/ch11_UDP.pdf

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

typedef struct pcb_t{
    uint16_t local_port;
    
    
}pcb_t;

int socket(int type);
int bind(int sockid, int port);
int sendto(int sockid, int destip, int dport, char *message, int len);
int recvfrom(int sockid, int *srcip, int *sport, char **message, int len);