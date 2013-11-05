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
routerGraph routers;

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
    memcpy(opkt, hello); //copy the data from hello into this packet. 

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
    int i;
    for (i = 0; i < numOfNeighbours; ++i) {
        COPY_IP(hello->neighbours[i], neighbours[i]);
    }
    head.messageLength = numOfNeighbours + 9; //head size + hello_size = 9
    return head;
}

/*
 * ARPResolve: this routine is responsible for local ARP resolution.
 * It consults the local ARP cache to determine whether a valid ARP entry
 * is present. If a valid entry is not present, a remote request is sent out
 * and the packet that caused the request is buffered. The buffer is flushed
 * when the reply comes in.
 */
int ARPResolve(gpacket_t *in_pkt) {
    uchar mac_addr[6];
    char tmpbuf[MAX_TMPBUF_LEN];

    in_pkt->data.header.prot = htons(IP_PROTOCOL);
    // lookup the ARP table for the MAC for next hop
    if (ARPFindEntry(in_pkt->frame.nxth_ip_addr, mac_addr) == EXIT_FAILURE) {
        // no ARP match, buffer and send ARP request for next
        verbose(2, "[ARPResolve]:: buffering packet, sending ARP request");
        ARPAddBuffer(in_pkt);
        in_pkt->frame.arp_bcast = TRUE; // tell gnet this is bcast to prevent recursive ARP lookup!
        // create a new message for ARP request
        ARPSendRequest(in_pkt);
        return EXIT_SUCCESS;
        ;
    }

    verbose(2, "[ARPResolve]:: sent packet to MAC %s", MAC2Colon(tmpbuf, mac_addr));
    COPY_MAC(in_pkt->data.header.dst, mac_addr);
    in_pkt->frame.arp_valid = TRUE;
    ARPSend2Output(in_pkt);

    return EXIT_SUCCESS;
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
            OSPFPRocessLSU(in_pkt);
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

/*-------------------------------------------------------------------------
 *                   A R P  T A B L E  F U N C T I O N S
 *-------------------------------------------------------------------------*/

/*
 * initialize the ARP table
 */
void ARPInitTable() {
    int i;

    tbl_replace_indx = 0;

    for (i = 0; i < MAX_ARP; i++)
        ARPtable[i].is_empty = TRUE;

    verbose(2, "[ARPInitTable]:: ARP table initialized.. ");
    return;
}

void ARPReInitTable() {
    ARPInitTable();
}

/*
 * Find an ARP entry matching the supplied IP address in the ARP table
 * ARGUMENTS: uchar *ip_addr: IP address to look up
 *            uchar *mac_addr: returned MAC address corresponding to the IP
 * The MAC is only set when the return status is EXIT_SUCCESS. If error,
 * the MAC address (mac_addr) is undefined.
 */
int ARPFindEntry(uchar *ip_addr, uchar *mac_addr) {
    int i;
    char tmpbuf[MAX_TMPBUF_LEN];

    for (i = 0; i < MAX_ARP; i++) {
        if (ARPtable[i].is_empty == FALSE &&
                COMPARE_IP(ARPtable[i].ip_addr, ip_addr) == 0) {
            // found IP address - copy the MAC address
            COPY_MAC(mac_addr, ARPtable[i].mac_addr);
            verbose(2, "[ARPFindEntry]:: found ARP entry #%d for IP %s", i, IP2Dot(tmpbuf, ip_addr));
            return EXIT_SUCCESS;
        }
    }

    verbose(2, "[ARPFindEntry]:: failed to find ARP entry for IP %s", IP2Dot(tmpbuf, ip_addr));
    return EXIT_FAILURE;
}

/*
 * add an entry to the ARP table
 * ARGUMENTS: uchar *ip_addr - the IP address (4 bytes)
 *            uchar *mac_addr - the MAC address (6 bytes)
 * RETURNS: Nothing
 */
void ARPAddEntry(uchar *ip_addr, uchar *mac_addr) {
    int i;
    int empty_slot = MAX_ARP;
    char tmpbuf[MAX_TMPBUF_LEN];

    for (i = 0; i < MAX_ARP; i++) {
        if ((ARPtable[i].is_empty == FALSE) &&
                (COMPARE_IP(ARPtable[i].ip_addr, ip_addr) == 0)) {
            // update entry
            COPY_IP(ARPtable[i].ip_addr, ip_addr);
            COPY_MAC(ARPtable[i].mac_addr, mac_addr);

            verbose(2, "[ARPAddEntry]:: updated ARP table entry #%d: IP %s = MAC %s", i,
                    IP2Dot(tmpbuf, ip_addr), MAC2Colon(tmpbuf + 20, mac_addr));
            return;
        }
        if (ARPtable[i].is_empty == TRUE)
            empty_slot = i;
    }

    if (empty_slot == MAX_ARP) {
        // ARP table full.. do the replacement
        // use the FIFO strategy: table replace index is the FIFO pointer
        empty_slot = tbl_replace_indx;
        tbl_replace_indx = (tbl_replace_indx + 1) % MAX_ARP;
    }

    // add new entry or overwrite the replaced entry
    ARPtable[empty_slot].is_empty = FALSE;
    COPY_IP(ARPtable[empty_slot].ip_addr, ip_addr);
    COPY_MAC(ARPtable[empty_slot].mac_addr, mac_addr);

    verbose(2, "[ARPAddEntry]:: updated ARP table entry #%d: IP %s = MAC %s", empty_slot,
            IP2Dot(tmpbuf, ip_addr), MAC2Colon(tmpbuf + 20, mac_addr));

    return;
}

/*
 * print the ARP table
 */
void ARPPrintTable(void) {
    int i;
    char tmpbuf[MAX_TMPBUF_LEN];

    printf("-----------------------------------------------------------\n");
    printf("      A R P  T A B L E \n");
    printf("-----------------------------------------------------------\n");
    printf("Index\tIP address\tMAC address \n");

    for (i = 0; i < MAX_ARP; i++)
        if (ARPtable[i].is_empty == FALSE)
            printf("%d\t%s\t%s\n", i, IP2Dot(tmpbuf, ARPtable[i].ip_addr), MAC2Colon((tmpbuf + 20), ARPtable[i].mac_addr));
    printf("-----------------------------------------------------------\n");
    return;
}

/*
 * Delete ARP entry with the given IP address
 */
void ARPDeleteEntry(char *ip_addr) {
    int i;

    for (i = 0; i < MAX_ARP; i++) {
        if ((ARPtable[i].is_empty == FALSE) &&
                (COMPARE_IP(ARPtable[i].ip_addr, ip_addr)) == 0) {
            ARPtable[i].is_empty = TRUE;
            verbose(2, "[ARPDeleteEntry]:: arp entry #%d deleted", i);
        }
    }
    return;
}

/*
 * send an ARP request to eventually process message,
 * a copy of which is now in the buffer
 */
void ARPSendRequest(gpacket_t *pkt) {
    arp_packet_t *apkt = (arp_packet_t *) pkt->data.data;
    uchar bcast_addr[6];
    char tmpbuf[MAX_TMPBUF_LEN];

    memset(bcast_addr, 0xFF, 6);

    /*
     * Create ARP REQUEST packet
     * ether header will be set in GNET_ADAPTER
     * arp header
     */
    apkt->hw_addr_type = htons(ETHERNET_PROTOCOL); // set hw type
    apkt->arp_prot = htons(IP_PROTOCOL); // set prtotocol address format

    apkt->hw_addr_len = 6; // address length
    apkt->arp_prot_len = 4; // protocol address length
    apkt->arp_opcode = htons(ARP_REQUEST); // set ARP request opcode

    // source hw addr will be set in GNET_ADAPTER
    // source ip addr will be set in GNET_ADAPTER
    COPY_MAC(apkt->dst_hw_addr, bcast_addr); // target hw addr

    COPY_IP(apkt->dst_ip_addr, gHtonl((uchar *) tmpbuf, pkt->frame.nxth_ip_addr)); // target ip addr

    // send the ARP request packet
    verbose(2, "[sendARPRequest]:: sending ARP request for %s",
            IP2Dot(tmpbuf, pkt->frame.nxth_ip_addr));

    // prepare sending.. to GNET adapter..

    COPY_MAC(pkt->data.header.dst, bcast_addr);
    pkt->data.header.prot = htons(ARP_PROTOCOL);
    // actually send the message to the other module..
    ARPSend2Output(pkt);

    return;
}


/*-------------------------------------------------------------------------
 *                   A R P  B U F F E R  F U N C T I O N S
 *-------------------------------------------------------------------------*/

/*
 * initialize buffer
 */
void ARPInitBuffer() {
    int i;

    buf_replace_indx = 0;

    for (i = 0; i < MAX_ARP_BUFFERS; i++)
        ARPbuffer[i].is_empty = TRUE;

    verbose(2, "[initARPBuffer]:: packet buffer initialized");
    return;
}

/*
 * Add a packet to ARP buffer: This packet is waiting resolution
 * ARGUMENTS: in_pkt - pointer to message that is to be copied into buffer
 * RETURNS: none
 */
void ARPAddBuffer(gpacket_t *in_pkt) {
    int i;
    gpacket_t *cppkt;

    // duplicate the packet..
    cppkt = duplicatePacket(in_pkt);

    // Find an empty slot
    for (i = 0; i < MAX_ARP_BUFFERS; i++) {
        if (ARPbuffer[i].is_empty == TRUE) {
            ARPbuffer[i].is_empty = FALSE;
            ARPbuffer[i].wait_msg = cppkt;
            verbose(2, "[addARPBuffer]:: packet stored in entry %d", i);
            return;
        }
    }

    // No empty spot? Replace a packet, we need to deallocate the old packet
    free(ARPbuffer[i].wait_msg);
    ARPbuffer[i].wait_msg = cppkt;
    verbose(2, "[addARPBuffer]:: buffer full, packet buffered to replaced entry %d",
            buf_replace_indx);
    buf_replace_indx = (buf_replace_indx + 1) % MAX_ARP_BUFFERS; // adjust for FIFO

    return;
}

/*
 * get a packet from the ARP buffer
 * ARGUMENTS: out_pkt - pointer at which packet matching message is to be copied
 *              nexthop - pointer to dest. IP address to search for
 * RETURNS: The function returns EXIT_SUCCESS if packet was found and copied,
 * or EXIT_FAILURE if it was not found.
 */
int ARPGetBuffer(gpacket_t **out_pkt, uchar *nexthop) {
    int i;
    char tmpbuf[MAX_TMPBUF_LEN];

    // Search for packet in buffer
    for (i = 0; i < MAX_ARP_BUFFERS; i++) {
        if (ARPbuffer[i].is_empty == TRUE) continue;
        if (COMPARE_IP(ARPbuffer[i].wait_msg->frame.nxth_ip_addr, nexthop) == 0) {
            // match found
            *out_pkt = ARPbuffer[i].wait_msg;
            ARPbuffer[i].is_empty = TRUE;
            verbose(2, "[ARPGetBuffer]:: found packet matching nexthop %s at entry %d",
                    IP2Dot(tmpbuf, nexthop), i);
            return EXIT_SUCCESS;
        }
    }
    verbose(2, "[ARPGetBuffer]:: no match for nexthop %s", IP2Dot(tmpbuf, nexthop));
    return EXIT_FAILURE;
}

/*
 * flush all packets from buffer matching the nexthop
 * for which we now have an ARP entry
 */
void ARPFlushBuffer(char *next_hop, char *mac_addr) {
    gpacket_t *bfrd_msg;
    char tmpbuf[MAX_TMPBUF_LEN];

    verbose(2, "[ARPFlushBuffer]:: Entering the function.. ");
    while (ARPGetBuffer(&bfrd_msg, next_hop) == EXIT_SUCCESS) {
        // a message is already buffered.. send it out..
        // TODO: include QoS routines.. for now they are removed!

        // send to gnetAdapter
        // no need to set dst_int_num -- why?

        verbose(2, "[ARPFlushBuffer]:: flushing the entry with next_hop %s ", IP2Dot(tmpbuf, next_hop));
        COPY_MAC(bfrd_msg->data.header.dst, mac_addr);
        ARPSend2Output(bfrd_msg);
    }

    return;
}
