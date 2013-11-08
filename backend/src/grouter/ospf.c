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
int numOfNeighbours, lsuSeq = 0;
int bcastLSUcnt = 0;
uint32_t aliveVal[MAXNODES];

LS_Packet LSTable[MAXNODES];
uint16_t LSTableSize = 1;
routerNode router;
extern mtu_entry_t MTU_tbl[MAX_MTU];		        // MTU table
extern pktcore_t *pcore;
extern interface_array_t netarray;



void OSPFinit() {
    printf("Inside OSPF\n");
    int thread_stat1, thread_stat2;
    //if( getMyIp(router.ipAddress) == EXIT_FAILURE ) return;
    numOfNeighbours = 0;
    pthread_t threadid1, threadid2;
    makeLSUPacket( LSTable );
    thread_stat1 = pthread_create(&(threadid1), NULL, (void *)OSPFBroadcastHello, (void *)NULL);
    thread_stat2 = pthread_create(&(threadid2), NULL, (void *)OSPFAlive, (void *)NULL);

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


/**
 * Sends a hello packet to all routers in the interface.  
 * @return Success or Failure. 
 */
void *OSPFBroadcastHello() {
    int count = 0, i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    //printf("In OSPFBroad.\n");
    while(1){
        interface_t *currIface = netarray.elem;
        ospf_packet_t *ospfMessage = helloInit();
        ospf_hello_t *hello = ospfMessage->data;
        printf("\nNEIGHBOURS DISOVERED SO FAR: %d\n", numOfNeighbours);
        for( i = 0; i < numOfNeighbours; i++ ){
            printf("%d.%d.%d.%d\n", neighbours[i][3], neighbours[i][2], neighbours[i][1], neighbours[i][0]);
        }
        printf("\nBROADCAST ROUND: %d, Number of interfaces: %d\n", ++count, netarray.count);
        interface_t *ifptr;
        for( i = 1; i <= netarray.count; i++ ){
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
    //ushort cksm = checksum(opkt, opkt->messageLength);
    //opkt->checksum = htons(cksm);
    //printf("SENDING TO interface %s\n",IP2Dot(tmpBuff,dst_ip) );
    IPOutgoingPacket(out_pkt, dst_ip, opkt->messageLength, 2, OSPF_PROTOCOL);
}

//fix this so that it creates a "Hello" msg which
//is added to a ospf packet. do LSU in the same way
ospf_packet_t* helloInit() {
    ospf_packet_t *head = malloc(sizeof (ospf_packet_t));
    head->type = HELLO;
    ospf_hello_t *hello =(ospf_hello_t *)((uchar *)head + 4*4);//assigning the Hello msg to the data of Header
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

LS_Packet* lsuInit() {
    ospf_packet_t *head = malloc(sizeof (ospf_packet_t));
    head->type = LSU;
    head->version = 2;
    head->areaID = 0;
    head->authType= 0;
    head->messageLength = 5; //have to put in correct size
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
            break;
        case LSU:
            OSPFProcessLSU(in_pkt);
            break;
        default:
            verbose(1, "PROTOCOL NOT FOUND IN OSPF PACKET");
    }
}

void OSPFProcessHello(gpacket_t *in_pkt){
    //printf("RECEIVED at OSPF ProcessHello.\n");
    ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
    int iphdrlen = ipkt->ip_hdr_len *4;
    ospf_packet_t *ospfhdr = (ospf_packet_t *)((uchar *)ipkt + iphdrlen);
    ospf_hello_t *hellomsg = ospfhdr->data;
    uint8_t source[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    COPY_IP(source, ospfhdr->sourceIP);
    int i, isKnownNeighbour = 0;
    if( numOfNeighbours == 0 ){
        memcpy(neighbours[0], source, 4);
        aliveVal[numOfNeighbours++] = hellomsg->routerDeadInter;
    }
    else{
        for( i = 0; i < numOfNeighbours; ++i){
            // compare ospfhdr->sourceIP to all neighbours;
            if (COMPARE_IP(source, neighbours[i]) == 0){
            //the source is known as my neighbour. 
                //source is alive
                aliveVal[i] = hellomsg->routerDeadInter;
                isKnownNeighbour = 1;
                break;
            }
        }
        if(isKnownNeighbour == 0){
            memcpy(neighbours[numOfNeighbours], source, 4);
            aliveVal[numOfNeighbours++] = hellomsg->routerDeadInter;
        }
    }
    /*if(!isKnownNeighbour){
       //PROBLEMS:
       //-appending at end of the LSU
       //-so problem with delete -MAKE SURE to LOCK when deleting
       //LSTable is array of LS_Packets
       LS_Packet *lss = LSTable;
       ospf_LSU* routerLinksUp = lss->data;
       int nol = routerLinksUp->numOfLinks;
       
       source[3] = 0;
       for( i = 1; i <= netarray.count; i++ ){
           if( memcmp( netarray.elem[i]->ip_addr, source, 3 ) == 0 ){
               COPY_IP(routerLinksUp->links[nol].linkID, source);
               COPY_IP(routerLinksUp->links[nol].linkData, netarray.elem[i]->ip_addr);
               break;
           }               
       }
       routerLinksUp->numOfLinks++;
       lss->linkSequenceNumber++;
       broadcastLSU( lss );//send updated LSU to everyone
    }*/
}

void *OSPFAlive(){
    sleep(4);
    int i;
    for( i = 0; i < numOfNeighbours; i++ ){
        aliveVal[i] -= 5;
        if (aliveVal[i] <= 0){
            aliveVal[i] = 0;
            //TODO: SEND LSU.
        }
    }
}

void makeLSUPacket( LS_Packet *lsp ){
    //LS_Packet *head;// = malloc(sizeof (LS_Packet));
    //fixing head
    lsp->lsAge = 0;
    lsp->lsType = 2;
    getMyIp(lsp->linkStateId);
    COPY_IP(lsp->advertRouterIp, lsp->linkStateId);
    lsp->linkSequenceNumber = lsuSeq++;
    lsp->lsChecksum = 0;
    lsp->lsLength = 0;//not sure
    //*lsp = *head;
    //memcpy( lsp, head, sizeof(LS_Packet));
    //copying local links into packet::
    
    ospf_LSU *lsu = (ospf_LSU *) lsp->data;
    lsu->numOfLinks = 0; //LATER change this to take in stubs?
    lsu->padding = 0;
}

void broadcastLSU(LS_Packet *lspkt){
    printf("\nLSU BROADCAST ROUND: %d\n", ++bcastLSUcnt);
    
    char tmpBuff[MAX_TMPBUF_LEN];
    
    gpacket_t *out_pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
    ip_packet_t *ipkt = (ip_packet_t*) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; // no IP header options!!
    ospf_packet_t *opkt = (ospf_packet_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
    memcpy( opkt, lsuInit(), sizeof(ospf_packet_t));
    LS_Packet* lsupkt = (ospf_LSU *) opkt->data;
    memcpy( lsupkt, lspkt, sizeof(LS_Packet));
    //fix message length calc
    //opkt->messageLength = 4 + 5 + 1 + (lsupkt->data-> numOfLinks * 4);
    //OSPF Header + LSA Header + ospf_LSU variables + number of links * sizeoflnk)
    int i;
    //SENDING to all interfaces
    interface_t *ifptr;
    for( i = 0; i <= netarray.count; i++ ){
        ifptr = netarray.elem[i];
        if( ifptr == NULL ){ 
            printf("NULL Interface Found\n");
            continue;
        }
        //currIface += sizeof(netarray->elem);
        COPY_IP(opkt->sourceIP, ifptr->ip_addr);
        //IPOutgoingPacket(out_pkt, ifptr->ip_addr, opkt->messageLength * 4, 2, OSPF_PROTOCOL);
        //printf("IfPTR value %s.\n", IP2Dot(tmpbuf, ifptr->ip_addr));
    }
    //printf("SENDING TO interface %s\n",IP2Dot(tmpBuff,dst_ip) );
}

void OSPFProcessLSU(gpacket_t *in_pkt){
    
    printf("RECEIVED LSU at OSPF\n");
    return;
    ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
    int iphdrlen = ipkt->ip_hdr_len *4;
    ospf_packet_t *ospfhdr = (ospf_packet_t *)((uchar *)ipkt + iphdrlen);
    LS_Packet *lspkt = (LS_Packet *) ospfhdr->data;
    //LS_Packet *lspkt2 = (LS_Packet *) LSTable[i];
    ospf_LSU* LSUhdr = (ospf_LSU *) lspkt->data;
    int i;
    LS_Packet *lsp = LSTable;
    for ( i = 0, ++lsp; i < LSTableSize; i++, ++lsp ){
        if(COMPARE_IP(lsp->advertRouterIp, lspkt->advertRouterIp)==0){
            if (lsp->linkSequenceNumber < lspkt->linkSequenceNumber){
                //memcpy((void*)(LSTable + i*sizeof(LS_Packet)), lspkt, sizeof(LS_Packet)); //POSSIBLE POINT OF FAILURE
                //  LSTable[i] = *lspkt;
                //  broadcastLSU(lspkt);
                return;
            }
        }
    }
    
    //memcpy(LSTable[LSTableSize++], lspkt, sizeof(LS_Packet));
   // LSTable[LSTableSize++] = *lspkt;
   // broadcastLSU(lspkt);
    
    
    //check table against own
    //int numOfLinks = LSUhdr->numOfLinks;
    //memcmp( mostRecentLSP, lspkt, DEFAULT_MTU - 20 );
    //int updateFlag = 0;
    /*
    if( IP_CMP( lspkt->advertRouterIp, mostRecentLSP->advertRouterIp ) == 0 ){
        if( lspkt->linkSequenceNumber > mostRecentLSP->linkSequenceNumber )
            updateFlag = 1;
    }
    else{
        updateFlag = 1;
    }*/
}
