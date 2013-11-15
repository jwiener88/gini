#include "udp.h"


pcb_t PCBtable[PCBTABLESIZE];
/**
 * Creates all of the static structures required for UDP. 
 * 
 */ 
void init(){
    int i;
    for(i = 0; i < PCBTABLESIZE; ++i){
        PCBtable[i].type = FREE;
    }
    
}
/** 
 * Creates a socket item, and returns an index to the PCB array. 
 * @param 
 */
int socket(int type){
    int i;
    if (type == 1){
        for (i = 0; i < PCBTABLESIZE; ++i){
            if (PCBtable[i].type == FREE){
                return i;
            }
        }
      
    }
    else{
        printf("IN UDP: SOCKET REQUESTED WITH UNRECOGNIZED TYPE\n");
    }
    
    return -1;
}
int bind(int sockid, int port){
    
}
int sendto(int sockid, int destip, int dport, char *message, int len){
    
}
int recvfrom(int sockid, int *srcip, int *sport, char **message, int len){
    
}
