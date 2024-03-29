#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include<netinet/if_ether.h>
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
    u_int8_t IPHeaderLength : 4; // I chaged order of HL and version because they printed reversed...
    u_int8_t version : 4;
    u_int8_t TOS;
    u_int16_t TL; //Total Length
    u_int16_t Id;
    u_int16_t flagOffset; //Fragment + offset;
    u_int8_t TTL; //Time to live
    u_int8_t ProtocolID; // ID == 6 : TCP, ID == 17: UDP
    u_int16_t HeaderChecksum;
    u_int32_t SourceIPAddress;
    u_int32_t DestinationIPAddress;
}IP;

typedef struct TCP//
{
    u_int16_t Source_PortNumber;
    u_int16_t Destination_PortNumber; //if Number == 80: http, Number == 443 : https
    u_int32_t SequenceNumber;
    u_int32_t AckNum;
    u_int8_t DataOffset;
    u_int8_t ReservednFlags;//Reserved + Flags
    u_int16_t WindowSize;
    u_int16_t CheckSum;
    u_int16_t URG;
}TCP;

#pragma pack(1)
typedef struct TCPData
{
    u_int8_t Data[10];
}TCPData;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    //struct pointer
    Ethernet *P_Ethernet;
    IP *P_Ip;
    TCP *P_Tcp;
    TCPData *P_TD;

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
    printf("-----------------------Ethernet---------------------------\n");
    printf("SourceMacAddress is : ");
    print_mac(P_Ethernet->Source_MacAddress);
    printf("DestinationMacAddress is : ");
    print_mac(P_Ethernet->Destination_MacAddress);
    printf("Ethernet Header Length is %d byte\n", sizeof(struct Ethernet));

    //IPHeader
    printf("-------------------------IP-------------------------------\n");
    if((ntohs((P_Ethernet->Ethernet_Type)) == ETHERTYPE_IP)){
        printf("It is IP!\n");

        P_Ip = (struct IP*)(packet + sizeof(struct Ethernet));
        printf("Source IP Address is : ");
        print_ip(&(P_Ip->SourceIPAddress));
        printf("Destination IP Address is : ");
        print_ip(&(P_Ip->DestinationIPAddress));
        printf("Header Length is %d Word(init32)\n", P_Ip->IPHeaderLength);
        printf("IP Length is %d byte!\n", P_Ip->IPHeaderLength * 4);

        //TCP Header
        printf("-------------------------TCP------------------------------\n");
        if((P_Ip->ProtocolID) == IPPROTO_TCP){
            printf("It is TCP!\n");
            P_Tcp =(struct TCP*)(packet + (sizeof(struct Ethernet) + P_Ip->IPHeaderLength *4));
            printf("SourcePort Number is : ");
            print_port(&(P_Tcp->Source_PortNumber));
            printf("DestinationPort Number is : ");
            print_port(&(P_Tcp->Destination_PortNumber));

            //TCP Header length
            //TCP Data length == Total length - (IHL + DataOffset)*4
            u_int16_t Total = ntohs(P_Ip->TL);
            printf("TotalLength is %d byte!\n", Total);
            printf("IPHeaderLength is %d byte!\n", P_Ip->IPHeaderLength * 4);
            printf("DataOffset is  %d byte!\n", (P_Tcp->DataOffset >> 4) * 4);
            printf("TCP Data Length is %d byte!\n", Total - ((P_Ip->IPHeaderLength) + (P_Tcp->DataOffset >> 4)) *4);

            int tcpDatalen = Total - (((P_Ip->IPHeaderLength) + (P_Tcp->DataOffset >> 4)) *4);
            if (tcpDatalen > 10){
                tcpDatalen = 10;
            }

            //print TCP Data
            P_TD = (struct TCPData*)(packet + (sizeof(struct Ethernet) +
                    P_Ip->IPHeaderLength * 4 + (P_Tcp->DataOffset >> 4) * 4));
                if (tcpDatalen != 0){
                    printf("There is TCP Data!\n");
                    for (int i = 1; i <= tcpDatalen; ++i){
                        if (i != tcpDatalen){
                            printf("%02X:",P_TD->Data[i]);
                        }
                        else {
                            printf("%02X\n", P_TD->Data[i]);
                        }

                    }
                }
                else{
                    printf("No TCP Data!\n");
                }
            }
        }
    }
  pcap_close(handle);
  return 0;
  }



