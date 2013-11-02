/*
 This file contains the functionality of OSPF
 */


//All of this may need to move to the header. 
typedef struct _ospf_header{
    uint8_t version = 2;
    uint8_t type;
    uint16_t messageLenght;
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
    _ospf_header header;
    uint32_t netMask;
    uint16_t interval;
    uint8_t options;
    uint8_t priority;
    uint32_t routerDeadInter;
    uint8_t desigIP[4];
    uint8_t backupDesigIP[4];
  //  neighbour_ips* neighbours;   //unsure if we want a pointer in a header
} _ospf_hello_head;

//Not used in this project but we have it anyways.
typedef struct _ospf_datab_description {
    _ospf_header header;
    uint16_t interfaceMTU;
    uint8_t options;
    uint16_t IMS = 0; //change this with bitwise OR ( | ).
    uint32_t databaseSN;
    
    // Everything after here should probably be in a new struct. 
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
    uint32_t ls_type, link_id, ARIP; 
}_ospf_LS_request;