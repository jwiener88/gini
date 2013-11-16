#include "mtu.h"
#include "ip.h"


#define PCBTABLESIZE 25
#define FREE 0
#define IN_USE 1 

typedef struct udp_pkt {
//useful reference: http://medusa.sdsu.edu/network/CS576/Lectures/ch11_UDP.pdf

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
    udp_pkt_t* pkt; //the packet we are interested in. 
}udp_pseudo_header_t;

typedef struct pcb_t{
    uint16_t status;
    uint16_t process_id;
    uint16_t port;
    uint16_t queue_number;
    
    
}pcb_t;

int sendUDPpacket(gpacket_t *gPckt, uint8_t destIP[], uint16_t destport, uint16_t localport, char* message, int len); 
int newSocket(int type);
int bindSocket(int sockid, int port);
int UDPsendto(int sockid, uint8_t *destip, int dport, char *message, int len);
int UDPrecvfrom(int sockid, int *srcip, int *sport, char **message, int len);
int UDPprocessPacket(gpacket_t *in_pkt);