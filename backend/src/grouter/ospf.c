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
int numOfNeighbours, lsuSeq;
int bcastLSUcnt;
uint32_t aliveVal[MAXNODES];

LS_Packet LSTable[MAXNODES];
uint16_t LSTableSize;
routerNode router;
extern mtu_entry_t MTU_tbl[MAX_MTU];		        // MTU table
extern pktcore_t *pcore;
extern interface_array_t netarray;



void OSPFinit() {
    printf("Starting OSPF.\n");
    int thread_stat1, thread_stat2;
    numOfNeighbours = 0, bcastLSUcnt = 0;
    pthread_t threadid1, threadid2;
    LSUInit( LSTable );
    thread_stat1 = pthread_create(&(threadid1), NULL, (void *)OSPFBroadcastHello, (void *)NULL);
    //thread_stat2 = pthread_create(&(threadid2), NULL, (void *)OSPFAlive, (void *)NULL);
}

void LSUInit( LS_Packet *lsp ){
    //fixing head
    lsp->lsAge = 0;
    lsp->lsType = 2;
    getMyIp(lsp->linkStateId);
    COPY_IP(lsp->advertRouterIp, lsp->linkStateId);
    lsp->linkSequenceNumber = lsuSeq++;
    lsp->lsChecksum = 0;
    lsp->lsLength = 5 + 1 + 0;//LS_Packet Header, LSU header, number of links
        
    ospf_LSU *lsu = (ospf_LSU *) lsp->data;
    lsu->numOfLinks = 0; //LATER change this to take in stubs?
    lsu->padding = 0;
    LSTableSize = 1;
    lsuSeq = 0;
}

void *OSPFBroadcastHello() {
    int count = 0, i, j;
    char tmpbuf[MAX_TMPBUF_LEN];
    while(1){
        interface_t *currIface = netarray.elem;
        ospf_packet_t *ospfMessage = getHello();
        ospf_hello_t *hello = ospfMessage->data;
        printf("\nNEIGHBOURS DISOVERED SO FAR: %d\n", numOfNeighbours);
        for( i = 0; i < numOfNeighbours; i++ ){
            uchar *ipp = &(neighbours[i]);
            printf("%s\n", IP2Dot(tmpbuf, ipp));
        }
        printf("\nBROADCAST ROUND: %d, Number of interfaces: %d\n", ++count, netarray.count);
        interface_t *ifptr;
        for( i = 1; i <= netarray.count; i++ ){
            ifptr = netarray.elem[i];
            if( ifptr == NULL ){ 
                printf("NULL Interface Found\n");
                continue;
            }
            //COPY_IP
            //Sending the OSPF Packet along with own interface IP
            OSPFSendHello(ospfMessage, ifptr->ip_addr);
        }
        sleep(hello->interval);
    }
}

int OSPFSendHello(ospf_packet_t* hello, uchar *dst_ip){
    char tmpBuff[MAX_TMPBUF_LEN];
    //Creating a General Packet to send to the IP Layer
    gpacket_t *out_pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
    //Assuming IP Packet starts at General Packet's data.data
    ip_packet_t *ipkt = (ip_packet_t*) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; //IP without header options
    //Assuming OSPF Packet starts right after the IP Packet
    ospf_packet_t *opkt = (ospf_packet_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
    
    //The OSPF Packet "hello" is copied to the appropriate address of the General Packet
    memcpy(opkt, hello, hello->messageLength * 4);
    //The OSPF Packet's source IP has not previously been set. It's the interface's IP.
    COPY_IP(opkt->sourceIP, dst_ip);
    char tmpbuf[MAX_TMPBUF_LEN];
    //printf("Sending HELLO to %s.\n", IP2Dot(tmpbuf, opkt->sourceIP));
    //Not using checksum
    //opkt->checksum = 0;
    
    //Sending the General Packet to the IP Layer
    IPOutgoingPacket(out_pkt, dst_ip, opkt->messageLength, 2, OSPF_PROTOCOL);
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

//fix this so that it creates a "Hello" msg which
//is added to a ospf packet. do LSU in the same way
ospf_packet_t* getHello() {
    //Create OSPF Packet
    ospf_packet_t *head = malloc(sizeof (ospf_packet_t));
    //Initialize header
    head->version = 2;
    head->type = HELLO;
    head->messageLength = NULL;
    //head->sourceIP = NULL;
    head->areaID = 0;
    head->checksum = NULL;
    head->authType= 0;
    //Create a Hello Message and point it to the data section of head
    ospf_hello_t *hello =(ospf_hello_t *)(head->data);
    //Initialize Hello message into header
    hello->netMask = 0xFFFFFF00;
    hello->interval = 10;
    hello->options = 0;
    hello->priority = 0;
    hello->routerDeadInter = 40;
    
    int i;
    for (i = 0; i < numOfNeighbours; ++i){
        COPY_IP(hello->neighbours[i], neighbours[i]);
    }
    //hello header size + num of neighbours [size in words]
    head->messageLength = 9 + numOfNeighbours;
    //PPOF
    return head;
}

ospf_packet_t* getLSU() {
    //Create OSPF Packet
    ospf_packet_t *head = malloc(sizeof (ospf_packet_t));
    //Initialize header
    head->version = 2;
    head->type = LSU;
    head->messageLength = NULL;
    //head->sourceIP = NULL;
    head->areaID = 0;
    head->checksum = NULL;
    head->authType= 0;
    //Copy LSU Message from LSTable and point it to the data section of head
    LS_Packet *lsu =(LS_Packet *)(head->data);
    memcpy(lsu, LSTable, sizeof(LS_Packet));
    head->messageLength = 4 + lsu->lsLength;
    return head;
}


void OSPFProcess(gpacket_t *in_pkt) {
    ip_packet_t *ip_pkt = (ip_packet_t *) in_pkt->data.data;
    ospf_packet_t *ospf_hdr = (ospf_packet_t *) ((uchar *) ip_pkt + ip_pkt->ip_hdr_len * 4);
    char tmpbuf[MAX_TMPBUF_LEN];
    //printf("RECEIVED HELLO from %s.\n", IP2Dot(tmpbuf, ospf_hdr->sourceIP));
    //printf("Received OSPF Type: %d\n", ospf_hdr->type );
    //printf("Received OSPF Version: %d\n", ospf_hdr->version );
    //printf("RECEIVED HELLO from %s.\n", IP2Dot(tmpbuf, ospf_hdr->sourceIP));
    //return;
    switch (ospf_hdr->type) {
        case HELLO:
            OSPFProcessHello(ospf_hdr); //TODO: implemnt this function.
            break;
        case LSU:
            OSPFProcessLSU(ospf_hdr);
            break;
        case DATABASEDesc:
            break;
        case LSR:
            break;
        default:
            verbose(1, "PROTOCOL NOT FOUND IN OSPF PACKET");
            printf("Type: %d\n",ospf_hdr->type);
    }
}

void OSPFProcessHello(ospf_packet_t *ospfhdr){
    //Find the Hello Message
    ospf_hello_t *hellomsg = ospfhdr->data;
    uint8_t source[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    COPY_IP(source, ospfhdr->sourceIP);
    printf("RECEIVED HELLO from %s.\n", IP2Dot(tmpbuf, source));
    int i, isKnownNeighbour = 0;
    if( numOfNeighbours == 0 ){
        COPY_IP(neighbours[numOfNeighbours], source);
        aliveVal[numOfNeighbours++] = hellomsg->routerDeadInter;      
    }
    else{
        for( i = 0; i < numOfNeighbours; ++i){
            // compare ospfhdr->sourceIP to all neighbours;
            if (COMPARE_IP(source, neighbours[i]) == 0){
            //the source is known neighbour and it's alive
                aliveVal[i] = hellomsg->routerDeadInter;
                isKnownNeighbour = 1;
                break;
            }
        }
        if(isKnownNeighbour == 0){
            COPY_IP(neighbours[numOfNeighbours], source);
            aliveVal[numOfNeighbours++] = hellomsg->routerDeadInter;
        }
    }
    if(isKnownNeighbour == 0){
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
       lss->lsLength += sizeof(lnk);
       OSPFBroadcastLSU( );//send updated LSU to everyone
    }
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



void OSPFBroadcastLSU(){
    printf("\nLSU BROADCAST ROUND: %d\n", ++bcastLSUcnt);
    
    char tmpBuff[MAX_TMPBUF_LEN];
    //Creating a General Packet to send to the IP Layer
    gpacket_t *out_pkt = (gpacket_t*) malloc(sizeof (gpacket_t));
    //Assuming IP Packet starts at General Packet's data.data
    ip_packet_t *ipkt = (ip_packet_t*) (out_pkt->data.data);
    ipkt->ip_hdr_len = 5; // IP without header options
    //Assuming OSPF Packet starts right after the IP Packet
    ospf_packet_t *opkt = (ospf_packet_t *) ((uchar *) ipkt + ipkt->ip_hdr_len * 4);
    
    memcpy( opkt, getLSU(), sizeof(ospf_packet_t));
    int i;
    //SENDING to all interfaces [CURRENTLY regardless of UML or Router]
    interface_t *ifptr;
    for( i = 1; i <= netarray.count; i++ ){
        ifptr = netarray.elem[i];
        if( ifptr == NULL ){ 
            printf("NULL Interface Found\n");
            continue;
        }
       COPY_IP(opkt->sourceIP, ifptr->ip_addr);
       //printf("Sending LSU Packet to \n");
       IPOutgoingPacket(out_pkt, ifptr->ip_addr, opkt->messageLength, 2, OSPF_PROTOCOL);
    }
}

void OSPFProcessLSU(ospf_packet_t *ospfhdr){
    
    LS_Packet *lspkt = ospfhdr->data;
    uint8_t source[4];
    char tmpbuf[MAX_TMPBUF_LEN];
    COPY_IP(source, ospfhdr->sourceIP);
    printf("RECEIVED LSU from %s.\n", IP2Dot(tmpbuf, source));
    ospf_LSU* newlinks = (ospf_LSU *) lspkt->data;
    int i, found = 0;
    LS_Packet *lsp = (LS_Packet *)LSTable;
    //Go through list of current entries in LSTable
    for ( i = 0; i < LSTableSize; ++i ){ //starts from 0 as this
        //way it's easier to prevent using LSU originally sent out by self
        lsp++;
        if(COMPARE_IP(lsp->advertRouterIp, lspkt->advertRouterIp)==0){
            if (lsp->linkSequenceNumber < lspkt->linkSequenceNumber){
                memcpy( lsp, lspkt, sizeof(LS_Packet) );
                found = 1;
                //OSPFForwardLSU( i );
            }
            else{
                printf("LSU received OWN or OLD\n");
                return; //old LSU. Don't save, don't forward.
            }
            
        }
    }
    if( found == 0 ){//An LSU received from this router for the first time
        LSTableSize++;
        printf("LSTABLE SIZE INCREASED\n");
        memcpy( lsp, lspkt, sizeof(LS_Packet) );
        //OSPFForwardLSU( i );
    }
}

void OSPFForwardLSU( int i ){
    //do jhamela
    /*ospf_packet_t *opkt = getLSU();
    LS_Packet *lsu =(LS_Packet *)(opkt->data);
    LS_Packet *lsp = (LS_Packet *)LSTable;
    memcpy(lsu, lsp + i, sizeof(LS_Packet));
    opkt->messageLength = 4 + lsu->lsLength;
    int i;
    //SENDING to all interfaces [CURRENTLY regardless of UML or Router]
    interface_t *ifptr;
    for( i = 1; i <= netarray.count; i++ ){
        ifptr = netarray.elem[i];
        if( ifptr == NULL ){ 
            printf("NULL Interface Found\n");
            continue;
        }
       COPY_IP(opkt->sourceIP, ifptr->ip_addr);
       //printf("Sending LSU Packet to \n");
       IPOutgoingPacket(out_pkt, ifptr->ip_addr, opkt->messageLength, 2, OSPF_PROTOCOL);
    }*/
}

/*//printf("RECEIVED at OSPF ProcessHello.\n");
    ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
    int iphdrlen = ipkt->ip_hdr_len *4;
    //Find the OSPF Packet location in General Packet
    ospf_packet_t *ospfhdr = (ospf_packet_t *)((uchar *)ipkt + iphdrlen);*/