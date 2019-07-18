#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "pcap_test.h"

//code for IPv4 & TCP ^^

typedef struct Ethernet //14byte
{
    u_int8_t Destination_MacAddress[6];
    u_int8_t Source_MacAddress[6];
    u_int16_t Ethernet_Type;//if Type == 0x0800: IPv4, Type==0x0806: ARP
}Ethernet;

typedef struct IP //HeaderLength * 4 == sizeof(struct IP)
{
    u_int8_t HeaderLength : 4; // I chaged order of HL and version because they printed reversed...
    u_int8_t version : 4;
    u_int8_t TOS;
    u_int16_t TL; //Total Length
    u_int16_t Id;
    u_int16_t flagOffset; //Fragment + offset;
    u_int8_t TTL; //Time to live
    u_int8_t ProtocolID; // ID == 6 : TCP, ID == 17: UDP
    u_int16_t HeaderChecksum;
    u_int8_t SourceIPAddress[4];
    u_int8_t DestinationIPAddress[4];
}IP;

typedef struct TCP//
{
    u_int8_t Source_PortNumber[2];
    u_int8_t Destination_PortNumber[2]; //if Number == 80: http, Number == 443 : https
    u_int32_t SequenceNumber;
    u_int32_t AckNum;
    u_int8_t HeaderLength : 4;
    u_int16_t ReservednFlags : 12;//Reserved + Flags
    u_int16_t WindowSize;
    u_int16_t CheckSum;
    u_int16_t URG;
}TCP;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    //struct pointer
    Ethernet *P_Ethernet;
    IP *P_Ip;
    TCP *P_Tcp;

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("\n");
    //Ethernet
    P_Ethernet = (struct Ethernet*)packet;
    printf("----------------------------Ethernet--------------------------------\n");
    printf("SourceMacAddress is : ");
    print_mac(P_Ethernet->Source_MacAddress);
    printf("DestinationMacAddress is : ");
    print_mac(P_Ethernet->Destination_MacAddress);
    printf("Ethernet Header Length is %d byte\n", sizeof(struct Ethernet));

    //IPHeader
    printf("------------------------------IP------------------------------------\n");
    if(uint16_t(ntohs((P_Ethernet->Ethernet_Type)) == 0x0800)){
        printf("It is IP!\n");

        P_Ip = (struct IP*)(packet + sizeof(struct Ethernet));
        printf("Source IP Address is : ");
        print_ip(P_Ip->SourceIPAddress);
        printf("Destination IP Address is : ");
        print_ip(P_Ip->DestinationIPAddress);
        printf("Header Length is %d Word(init32)\n", P_Ip->HeaderLength);
        printf("IP Length is %d byte!\n", P_Ip->HeaderLength * 4);

        //TCP Header
        printf("------------------------------TCP-----------------------------------\n");
        if(uint8_t(P_Ip->ProtocolID) == 0x06){
            printf("It is TCP!\n");
            P_Tcp =(struct TCP*)(packet+ + sizeof(struct Ethernet) + sizeof(P_Ip->HeaderLength *4));
            printf("SourcePort Number is : ");
            print_port(P_Tcp->Source_PortNumber);
            printf("DestinationPort Number is : ");
            print_port(P_Tcp->Destination_PortNumber);

            //TCP Header length
            printf("Header Length is %d Word(init32)\n", P_Tcp->HeaderLength);
            printf("TCP Header Length is %d byte.\n", P_Tcp->HeaderLength * 4);
            if((P_Tcp->Destination_PortNumber[0]) << 8 |
                    (P_Tcp->Destination_PortNumber[1]) == 0x0050){
                printf("-----------------------------http------------------------------------\n");
                printf("It is http!\n");
                packet += sizeof(P_Tcp->HeaderLength * 4); //move to http
                printf("%X", P_Tcp->HeaderLength);
                //printf("%.30s",packet);
                for (int i = 0; i < 10; i++){
                    if(i != 9){
                        printf("%02X:", packet[i]);
                    }
                    else {
                        printf("%02X\n", packet[i]);
                    }
                                        }
                printf("======================================================================\n");
            printf("\n");
            }
        }
    }
  }
  pcap_close(handle);
  return 0;
}

