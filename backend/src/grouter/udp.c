#include "udp.h"
#include "packetcore.h"
#include "ip.h"
#include "protocols.h"
#include "simplequeue.h"
#include "grouter.h"
#include "message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



pcb_t PCBtable[PCBTABLESIZE];
simplequeue_t *queueList[PCBTABLESIZE];
int queues;

/**
 * Creates all of the static structures required for UDP. 
 * 
 */
void init() {
    int i;
    queues = 0;
    for (i = 0; i < PCBTABLESIZE; ++i) {
        PCBtable[i].status = FREE;
    }

}

int sendUDPpacket(gpacket_t *gPckt, uint8_t destIP[], uint16_t destport, uint16_t localport, char* message, int len) {
    gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof (gpacket_t));
    ip_packet_t *ipkt = (ip_packet_t *) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; // no IP header options!!
    udp_pkt_t *udp_datagram = (udp_pkt_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);

    int i;
    char tmpbuf[64];

    udp_datagram->source_port = localport;
    udp_datagram->dest_port = destport;
    udp_datagram->checksum = 0;
    memcpy(udp_datagram->data, message, len);


    while (len % 4 != 0)
        *(udp_datagram->data + len++) = 0; //pad with 0s. 

    udp_datagram->length = len + 8; //8 byte header + len characters. 

    verbose(2, "[MKUDPPACKET]:: SENDING UDP TO %s", IP2Dot(tmpbuf, destIP));

    //send packet out with UDP_PROTOCOL
    IPOutgoingPacket(out_pkt, destIP, udp_datagram->length, 1, UDP_PROTOCOL);

    return EXIT_FAILURE;
}

/** 
 * Creates a socket item, and returns an index to the PCB array. 
 * @param 
 */
int newSocket(int type) {
    int i;
    if (type == 1) {
        for (i = 0; i < PCBTABLESIZE; ++i) {
            if (PCBtable[i].status == FREE) {
                PCBtable[i].status = IN_USE;
                PCBtable[i].port = 0;
                return i;
            }
        }
    } else {
        printf("IN UDP: SOCKET REQUESTED WITH UNRECOGNIZED TYPE\n");
    }

    return -1;
}

int bindSocket(int sockid, int port) {
    if (PCBtable[sockid].port == 0) {
        PCBtable[sockid].port = port;
        return EXIT_SUCCESS;
    } else {
        return EXIT_FAILURE;
    }
}

int UDPsendto(int sockid, uint8_t *destip, int dport, char *message, int len) {
    gpacket_t *gpckt = malloc(sizeof (gpacket_t)); //create a general packet
    sendUDPpacket(gpckt, destip, dport, PCBtable[sockid].port, message, len);

    return len;
}

int UDPrecvfrom(int sockid, int *srcip, int *sport, char **message, int len) {
    pcb_t *pcb = &PCBtable[sockid];
    int queue = pcb->queue_number;
    if(queue == 0){
        queue = queues++;
        queueList[queue] = createSimpleQueue("",0,FALSE,FALSE);
    }
    writeQueue(queue, message, len);
    
    return len;
}

/*
 * 
 */
int UDPProcess(gpacket_t *in_pkt) {
    verbose(1, "[UDPProcess]:: packet received for processing");
    ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
    int iphdrlen = ip_pkt->ip_hdr_len * 4;
    udp_pkt_t *udp_pkt = (udp_pkt_t *) ((uchar *) ip_pkt + iphdrlen);
    //create pesuedo header.
    udp_pseudo_header_t *psuedo = malloc(sizeof (udp_pseudo_header_t));
    COPY_IP(psuedo->dest_ip, ip_pkt->ip_dst);
    COPY_IP(psuedo->source_ip, ip_pkt->ip_src);
    psuedo->protocol = ip_pkt->ip_prot;
    psuedo->pkt = udp_pkt;
    psuedo->udp_length = udp_pkt->length;
    uint16_t cksum = checksum((uchar *) psuedo, (udp_pkt->length + 12) / 2); // size = payload (given) + UDP_header
    //compare checksum
    if (cksum == 0) {
        //find port in PCB
        int sockid, i;
        for (i = 0; i < PCBTABLESIZE; i++) {
            if (PCBtable[i].port == udp_pkt->dest_port) {
                sockid = i;
                return UDPrecvfrom(sockid, ip_pkt->ip_src, udp_pkt->source_port, udp_pkt->data, udp_pkt->length);
            }
        }
    }
    //No socket found. 
    return EXIT_FAILURE;
}
