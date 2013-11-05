#include "grouter.h"

/*
 This file contains the functionality of OSPF
 */

#define MAXNODES 50
#define MAXSIZE 300
//All of this may need to move to the header. 
typedef struct ospf_packet_t{
    uint8_t version = 2;
    uint8_t type;
    uint16_t messageLength; //in words (4byts/word)
    uint8_t sourceIP[4];   //4 8-bit numbers 
    uint32_t areaID = 0; //Edit: areadID is 0 for this project
    uint16_t checksum;
    uint16_t authType = 0; //Edit: this is 0 as well
    uint8_t data[DEFAULT_MTU-16-20]; //minus this header, minus ip header. 
} ospf_packet_t;

#define HELLO                   1
#define DATABASEDesc            2
#define LSR                     3
#define LSU                     4

//Linked list to handle a list of neighbours, we may want 
// this to be just an array.

//typedef struct neighbour_ips{
//    uint8_t neighbours[4];
//    neighbour_ips* next;
//}neighbour_ips;

typedef struct _ospf_hello_msg{
    uint32_t netMask = 0xFFFFFF00;
    uint16_t interval = 10;
    uint8_t options=0;
    uint8_t priority = 0;
    uint32_t routerDeadInter = 40;
    uint8_t desigIP[4] = 0;
    uint8_t backupDesigIP[4] = 0;
    uint8_t neighbours[][4]; //flexible array for IPs
    //when initialized, we need to calloc this struct. 
} _ospf_hello_msg;

//Not used in this project but we have it anyways.
//typedef struct _ospf_datab_description {
//    uint16_t interfaceMTU;
//    uint8_t options;
//    uint16_t IMS = 0; //change this with bitwise OR ( | ).
//    uint32_t databaseSN;
//    
//    // Everything after here should probably be in a new struct. 
//    // but we aren't using it anyways. 
//    uint16_t lsAge;
//    uint8_t lsOptions;
//    uint8_t lsType;
//    uint32_t linkID;
//    uint32_t ARIP;
//    uint32_t linkSequenceNumber;
//    uint16_t linkChecksum, LSlength;
//    
//}_ospf_datab_description;

typedef struct _ospf_LS_request {
    uint32_t lsType, linkId;
    uint8_t advertRouterIp[4]; 
}_ospf_LS_request;

typedef struct _ospf_LSA {
    uint16_t lsAge = 0;
    uint16_t lsType;
    uint32_t linkStateId;
    uint8_t advertRouterIp[4];
    uint32_t linkSequenceNumber;
    uint16_t lsChecksum, lsLength;
}_ospf_LSA;

typedef struct _update_link{
    uint32_t linkID;
    uint32_t linkData;
    uint8_t type;
    uint8_t pad1 = 0;
    uint16_t pad2 = 0;
    uint16_t pad3 = 0;
    uint16_t metric = 1;
}LINK;

typedef struct _ospf_LS_update {
    _ospf_LSA lsaHeader;
    uint16_t padding = 0;
    uint16_t numOfLinks;
    LINK links[];
};

typedef struct routerNode{
    uint8_t ipAddress[4];
    routerNode** children;
}routerGraph;
