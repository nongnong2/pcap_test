#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
//code for IPv4 & TCP ^^

#pragma pack(push, 1)
typedef struct Ethernet //14byte
{
    u_int8_t Destination_MacAddress[6];
    u_int8_t Source_MacAddress[6];
    u_int16_t Ethernet_Type;//if Type == 0x0800: IPv4, Type==0x0806: ARP
}Ethernet;

typedef struct IP //20byte
{
    u_int8_t Else[9];
    u_int8_t ProtocolID; // ID == 6 : TCP, ID == 17: UDP
    u_int16_t HeaderChecksum;
    u_int8_t SourceIPAddress[4];
    u_int8_t DestinationIPAddress[4];
}IP;

typedef struct TCP//20byte
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
#pragma pack(pop)
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

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
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
    printf("====================================================================\n");
    P_Ethernet = (struct Ethernet*)packet;
    printf("----------------------------Ethernet--------------------------------\n");
    printf("SourceMacAddress is : ");
    print_mac(P_Ethernet->Source_MacAddress);
    printf("DestinationMacAddress is : ");
    print_mac(P_Ethernet->Destination_MacAddress);

    //IPHeader
    printf("-------------------------------IP-----------------------------------\n");
    if(uint16_t(ntohs((P_Ethernet->Ethernet_Type)) == 0x0800)){
        printf("It is IP!\n");
        packet += sizeof (struct Ethernet); // move to IPHeader
        P_Ip = (struct IP*)packet;
        printf("Source IP Address is : ");
        print_ip(P_Ip->SourceIPAddress);
        printf("Destination IP Address is : ");
        print_ip(P_Ip->DestinationIPAddress);

        //TCP Header
        printf("---------------------------------TCP--------------------------------\n");
        if(uint8_t(P_Ip->ProtocolID) == 0x06){
            printf("It is TCP!\n");
            packet += sizeof (struct IP);
            printf("SourcePort Number is : ");
            print_port(P_Tcp->Source_PortNumber);
            printf("DestinationPort Number is : ");
            print_port(P_Tcp->Destination_PortNumber);
            //TCP Data & Location
            int HLength = P_Tcp->HeaderLength * 4; //TCP Header length
            printf("TCP Length is %X byte!\n", P_Tcp->HeaderLength);
            for (int i = 0; i < HLength; i++){
                printf("%02X",packet[i]);
            }
            printf("\n");
            printf("====================================================================\n");
        }

    }
    else {
        printf("Etehrnet type is %X. If is not 0x800 then It is not IPv4 ", uint16_t(ntohs((P_Ethernet->Ethernet_Type))));
        printf("Protocol ID is %X. If is not 0x06 then It is not TCP.", uint8_t(P_Ip->ProtocolID));
    }

  pcap_close(handle);
  return 0;
}
}
