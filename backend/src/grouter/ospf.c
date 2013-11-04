#include "ospf.h"


_ospf_hello_head mk_hello(){
    _ospf_hello_head hello_packet = malloc(sizeof(_ospf_hello_head));
    _ospf_header head = malloc(sizeof(_ospf_header));
    hello_packet.header = head;
    hello_packet.header.type = 1;
    
}