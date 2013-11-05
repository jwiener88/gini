#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include "protocols.h"
#include "arp.h"
#include "gnet.h"
#include "moduledefs.h"
#include "grouter.h"
#include "packetcore.h"
#include "ospf.h"
#include "gnet.c"


uint8_t neighbours[MAXNODES][4];
int numOfNeighbours;
routerNode routers;

void OSPFinit(int *ospfHellos) {
    int thread_stat;
    getMyIp(routers->ipAddress);
    numOfNeighbours = 0;
    thread_stat = pthread_create((pthread_t *)ospfHellos, NULL, OSPFBroadcastHello, NULL);
}

int getMyIp(uint8_t *myIp) {
    int count = 0;
    char ipBuffer[MAXNODES][4];
    int i, j;
    uint8_t minm[4];
    for (i = 0; i < 4; i++)
        minm[i] = 255;
    if ((count = findAllInterfaceIPs(MTU_tbl, ipBuffer)) > 0) {
        for (j = 0; j < count; j++) {
            int flag = 0;
            for (i = 0; i < 4; i++) {
                if (ipBuffer[j][i] < minm[i]) {
                    flag = 1;
                    break;
                }
            }
            if (flag) {
                COPY_IP(minm, ipBuffer[j]);
            }
        }
    } else return EXIT_FAILURE;
    COPY_IP(myIP, minm);

    return EXIT_SUCCESS;
}

extern pktcore_t *pcore;

/**
 * Sends a hello packet to all routers in the interface.  
 * @return Success or Failure. 
 */
int OSPFBroadcastHello() {
    int count, i, j;
    uint8_t ipBuffer[MAXNODES][4];
    while(1){
        if ((count = findAllInterfaceIPs(MTU_tbl, ipBuffer)) > 0) {
            //CREATE HELLO
            ospf_packet_t ospfMessage = helloInit();
            _ospf_hello_msg *hello = ospfMessage.data;
            //LOOP Send to all interfaceIPs
            for (i = 0; i < count; i++) {
                OSPFSendHello(&ospfMessage, ipBuffer[i]);
            }
            sleep(hello->interval);
            
        }
    }
    
    return EXIT_SUCCESS;
}

int OSPFSendHello(ospf_packet_t* hello, uint8_t ip[]) {
    char tmpBuff[MAX_TMPBUF_LEN];
    gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof (gpacket_t));
    ip_packet_t *ipkt = (ip_packet_t *) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; // no IP header options!!
    ospf_packet_t *opkt = (ospf_packet_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
    //this is the general ospf packet. 
    memcpy(opkt, hello, hello->messageLength*4); //copy the data from hello into this packet. 

    if (getMyIp(opkt->sourceIP) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    ushort cksm = checksum(opkt, opkt->messageLength);
    opkt->checksum = htons(cksm);
    verbose(2, "SENDING HELLO to %s", IP2Dot(tmpBuff, ip));
    IPOutgoingPacket(out_pkt, ip, opkt->messageLength, 1, OSPF_PROTOCOL);

}

ospf_packet_t helloInit() {
    ospf_packet_t* head = malloc(sizeof (ospf_packet_t));
    head.type = HELLO;
    _ospf_hello_msg* hello = malloc((5 + numOfNeighbours)*4);
    head->data = hello;
    head->version = 2;
    head->areaID = 0;
    head->authType= 0;
    hello->netMask = 0xFFFFFF00;
    hello->interval = 10;
    hello->options = 0;
    hello->priority = 0;
    hello->routerDeadInter = 40;
    
    int i;
    for (i = 0; i < numOfNeighbours; ++i) {
        COPY_IP(hello->neighbours[i], neighbours[i]);
    }
    head.messageLength = numOfNeighbours + 9; //head size + hello_size = 9
    return head;
}

/*
 * ARPProcess: Process a received ARP packet... from remote nodes. If it is
 * a reply for a ARP request sent from the local node, use it
 * to update the local ARP cache. Flush (dequeue, process, and send) any packets
 * that are buffered for ARP processing that match the ARP reply.

 * If it a request, send a reply.. no need to record any state here.
 */
void OSPFProcess(gpacket_t *in_pkt) {
    ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
    int iphdrlen = ip_pkt->ip_hdr_len * 4;
    ospf_packet_t *ospf_hdr = (ospf_packet_t *) ((uchar *) ip_pkt + iphdrlen);

    switch (ospf_hdr->type) {
        case HELLO:
            verbose(2, "[ICMPProcessPacket]:: ICMP processing for ECHO request");
            OSPFProcessHello(in_pkt); //TODO: implemnt this function.
            break;

        case DATABASEDesc:
            verbose(2, "[ICMPProcessPacket]:: ICMP processing for ECHO reply");
            //UNIMPLEMENTED
            break;

        case LSR:
            //UNIMPLEMENTED
            break;
        case LSU:
            OSPFProcessLSU(in_pkt);
            break;
        default:
            verbose(1, "PROTOCOL NOT FOUND IN OSPF PACKET");
    }
}

void OSPFProcessHello(gpacket_t *in_pkt){
    ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
    int iphdrlen = ipkt->ip_hdr_len *4;
    ospf_packet_t *ospfhdr = (ospf_packet_t *)((uchar *)ipkt + iphdrlen);
    _ospf_hello_msg *hellomsg = ospfhdr->data;
    int isKnownNeighbour = 0;
    int i;
    uint8_t source[4];
    COPY_IP(source, ospfhdr->sourceIP);
    for( i = 0; i < numOfNeighbours; ++i){
        // compare ospfhdr->sourceIP to all neighbours;
        if (COMPARE_IP(source, neighbours[i]) == 0){
        //the source is known as my neighbour. 
            isKnownNeighbour = 1;
            break;
        }
    }
    if(!isKnownNeighbour){
        memcpy(neighbours[numOfNeighbours++], source); 
    }
}

void OSPFProcessLSU(gpacket_t *in_pkt){
    
}
