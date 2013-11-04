/*
 This file contains the functionality of OSPF
 */


//All of this may need to move to the header. 
typedef struct _ospf_header{
    uint8_t version = 2;
    uint8_t type;
    uint16_t messageLength;
    uint8_t sourceIP[4];   //4 8-bit numbers 
    uint32_t areaID;
    uint16_t checksum;
    uint16_t authType;
    
    //Authentication goes here. 
} _ospf_header;

#define HELLO                   1
#define DATABASEDesc            2
#define LSR                     3
#define LSU                     4
#define LSA                     5

//Linked list to handle a list of neighbours, we may want 
// this to be just an array.

//typedef struct neighbour_ips{
//    uint8_t neighbours[4];
//    neighbour_ips* next;
//}neighbour_ips;

typedef struct _ospf_hello_head{
    _ospf_header header; //type should be 'HELLO' 
    uint32_t netMask = 0xFFFFFF00;
    uint16_t interval;
    uint8_t options;
    uint8_t priority;
    uint32_t routerDeadInter;
    uint8_t desigIP[4];
    uint8_t backupDesigIP[4];
    uint8_t[4][] neighbours; //flexible array for IPs
    //when initialized, we need to calloc this struct. 
} _ospf_hello_head;

//Not used in this project but we have it anyways.
typedef struct _ospf_datab_description {
    _ospf_header header;
    uint16_t interfaceMTU;
    uint8_t options;
    uint16_t IMS = 0; //change this with bitwise OR ( | ).
    uint32_t databaseSN;
    
    // Everything after here should probably be in a new struct. 
    // but we aren't using it anyways. 
    uint16_t LSage;
    uint8_t LSOptions;
    uint8_t LSType;
    uint32_t linkID;
    uint32_t ARIP;
    uint32_t linkSequenceNumber;
    uint16_t linkChecksum, LSlength;
    
}_ospf_datab_description;

typedef struct _ospf_LS_request {
    _ospf_header header;
    uint32_t ls_type, link_id;
    uint8_t advertRouterIp[4]; 
}_ospf_LS_request;

typedef struct _ospf_LS_advert {
    uint16_t ls_type;
    uint32_t link_id;
    uint8_t advertRouterIp[4];
    uint32_t sequenceNumber;
    uint16_t lsChecksum, lsLength;
}_ospf_LS_advert;

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
    _ospf_header ospfHeader;
    _ospf_LS_adver LSA_header;
    uint16_t padding = 0;
    uint16_t numOfLinks;
    LINK[] links;
};
