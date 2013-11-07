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
#include "gnet.h"
#include "mtu.h"
#include "ip.h"


uint8_t neighbours[MAXNODES][4];
int numOfNeighbours;
routerNode router;
extern mtu_entry_t MTU_tbl[MAX_MTU];		        // MTU table



void OSPFinit() {
    printf("Inside OSPF\n");
    int thread_stat;
    //if( getMyIp(router.ipAddress) == EXIT_FAILURE ) return;
    numOfNeighbours = 0;
    pthread_t threadid;
    thread_stat = pthread_create(&(threadid), NULL, (void *)OSPFBroadcastHello, (void *)NULL);
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
    COPY_IP(myIp, minm);

    return EXIT_SUCCESS;
}

extern pktcore_t *pcore;
extern interface_array_t netarray;
/**
 * Sends a hello packet to all routers in the interface.  
 * @return Success or Failure. 
 */
void *OSPFBroadcastHello() {
    int count = 0, i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    printf("In OSPFBroad.\n");
    while(1){
        interface_t *currIface = netarray.elem;
        ospf_packet_t *ospfMessage = helloInit();
        _ospf_hello_msg *hello = ospfMessage->data;
        printf("\nNEIGHBOURS DISOVERED SO FAR: %d\n", numOfNeighbours);
        for( i = 0; i < numOfNeighbours; i++ ){
            printf("%d.%d.%d.%d\n", neighbours[i][3], neighbours[i][2], neighbours[i][1], neighbours[i][0]);
        }
        printf("\nBROADCAST ROUND: %d, Number of interfaces: %d\n", ++count, netarray.count);
        interface_t *ifptr;
        for( i = 0; i < netarray.count; i++ ){
            ifptr = netarray.elem[i];
            if( ifptr == NULL ){ 
                printf("NULL Interface Found\n");
                continue;
            }
            //currIface += sizeof(netarray->elem);
            OSPFSendHello(ospfMessage, ifptr->ip_addr);
            //printf("IfPTR value %s.\n", IP2Dot(tmpbuf, ifptr->ip_addr));
        }
        printf("\n");
        sleep(hello->interval);
        
    }
}

/*void OSPFAlive(){
    sleep(40);
    int i;
    for( i = 0; i < numOfNeighbours; i++ ){
        
    }
}*/

int OSPFSendHello(ospf_packet_t* hello, uchar *dst_ip) {
    char tmpBuff[MAX_TMPBUF_LEN];
    
    gpacket_t *out_pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
    ip_packet_t *ipkt = (ip_packet_t*) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; // no IP header options!!
    ospf_packet_t *opkt = (ospf_packet_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
    
    //this is the general ospf packet. 
    memcpy(opkt, hello, hello->messageLength*4); //copy the data from hello into this packet. 
    //uncomment out this later
    COPY_IP(opkt->sourceIP, dst_ip);
//    if (getMyIp(opkt->sourceIP) == EXIT_FAILURE) {
//        return EXIT_FAILURE;
//    }

    //ushort cksm = checksum(opkt, opkt->messageLength);
    //opkt->checksum = htons(cksm);
    //verbose(2, "SENDING HELLO to %s", IP2Dot(tmpBuff, ip));
	//char tmpbuf[MAX_TMPBUF_LEN];
    printf("SENDING TO interface %s\n",IP2Dot(tmpBuff,dst_ip) );
    //printf("OSPF.c OSPF Type:%d\n", opkt->type);
    IPOutgoingPacket(out_pkt, dst_ip, opkt->messageLength, 2, OSPF_PROTOCOL);

}

//fix this so that it creates a "Hello" msg which
//is added to a ospf packet. do LSU in the same way
ospf_packet_t* helloInit() {
    ospf_packet_t *head = malloc(sizeof (ospf_packet_t));
    head->type = HELLO;
    _ospf_hello_msg *hello =(_ospf_hello_msg *)((uchar *)head + 4*4);//assigning the Hello msg to the data of Header
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
    head->messageLength = numOfNeighbours + 9; //head size + hello_size = 9
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
            OSPFProcessHello(in_pkt); //TODO: implemnt this function.
            break;

        case DATABASEDesc:
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
    printf("RECEIVED at OSPF ProcessHello.\n");
    ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
    int iphdrlen = ipkt->ip_hdr_len *4;
    ospf_packet_t *ospfhdr = (ospf_packet_t *)((uchar *)ipkt + iphdrlen);
    _ospf_hello_msg *hellomsg = ospfhdr->data;
    uint8_t source[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    COPY_IP(source, ospfhdr->sourceIP);
    if( numOfNeighbours == 0 ){
        memcpy(neighbours[numOfNeighbours++], source, 4);
    }
    else{
        int i, isKnownNeighbour = 0;
        for( i = 0; i < numOfNeighbours; ++i){
            // compare ospfhdr->sourceIP to all neighbours;
            if (COMPARE_IP(source, neighbours[i]) == 0){
            //the source is known as my neighbour. 
                isKnownNeighbour = 1;
                break;
            }
        }
        if(isKnownNeighbour == 0){
            memcpy(neighbours[numOfNeighbours++], source, 4);
        }
    }
}

void OSPFProcessLSU(gpacket_t *in_pkt){
    
}
