#include "pcap_test.h"
#include <stdint.h>
#include <stdio.h>

void print_mac(uint8_t *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t *ip){
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint8_t *port){
    printf("%d\n", (port[0] << 8) | port[1]);
}
