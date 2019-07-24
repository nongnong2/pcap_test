#include "pcap_test.h"
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

void print_mac(uint8_t *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t *ip){
    printf("%d.%d.%d.%d\n",
           (ntohl(*ip) & 0xFF000000) >> 24,
           (ntohl(*ip) & 0x00FF0000) >> 16,
           (ntohl(*ip) & 0x0000FF00) >> 8,
           (ntohl(*ip) & 0x000000FF)
           );
}

void print_port(uint16_t *port){
    printf("%d\n", ntohs(*port));
}

