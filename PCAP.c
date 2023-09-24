#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

#pragma pack (push,1)

typedef struct EthernetHeader 
{
    unsigned char des_mac[6];
    unsigned char src_mac[6];
    unsigned short type;
}EthernetH;

typedef struct IPHeader 
{
    unsigned char version : 4;
    unsigned char ihl : 4;
    unsigned char tos;
    unsigned short len;
    unsigned short id;
    unsigned char flagsx : 1;
    unsigned char flagsD : 1;
    unsigned char flagsM : 1;
    unsigned int fO : 13;
    unsigned char ttl;
    unsigned char protocal;
    unsigned short headerCheck;
    struct in_addr srcadd;
    struct in_addr dstadd;
}IPH;

typedef struct TCPHeader 
{
    unsigned short srcport;
    unsigned short dstport;
    unsigned int sequence_number;
    unsigned int acknowledgement_number;
    unsigned char offset : 4;
    unsigned char reserved : 6;
    unsigned char flagsC : 1;
    unsigned char flagsE : 1;
    unsigned char flagsU : 1;
    unsigned char flagsA : 1;
    unsigned char flagsP : 1;
    unsigned char flagsR : 1;
    unsigned char flagsS : 1;
    unsigned char flagsF : 1;
    unsigned short window;
    unsigned short checksum;
    unsigned short u_pointer;
}TCPH;

void PrintEthernetHeader(const u_char* packet) 
{
    EthernetH* eh;
    eh = (EthernetH*)packet;
    printf("\n======== Ethernet Header ========\n");
    printf("Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n", eh->des_mac[0], eh->des_mac[1], eh->des_mac[2], eh->des_mac[3], eh->des_mac[4], eh->des_mac[5]);
    printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n", eh->src_mac[0], eh->src_mac[1], eh->src_mac[2], eh->src_mac[3], eh->src_mac[4], eh->src_mac[5]);
}

void PrintIPHeader(const u_char* packet) 
{
    IPH* ih;
    ih = (IPH*)packet;
    printf("======== IP Header ========\n");
    if (ih->protocal == 0x06) printf("TCP\n");
    printf("Src IP  : %s\n", inet_ntoa(ih->srcadd));
    printf("Dst IP  : %s\n", inet_ntoa(ih->dstadd));
}

void PrintTCPHeader(const u_char* packet) 
{
    TCPH* th;
    th = (TCPH*)packet;
    printf("======== TCP Heather ========\n");
    printf("Src Port : %d\n", ntohs(th->srcport));
    printf("Dst Port : %d\n", ntohs(th->dstport));
}

int main(int argc, char* argv[]) 
{
    if (argc != 2) {
        printf("Interface ?\n");
        exit(1);
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    IPH* tlen;
    u_int lengh;
    pcap_t* handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);

    if (handle == NULL) 
    {
        printf("%s : %s \n", dev, errbuf);
        exit(1);
    }

    while (1) 
    {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) exit(1);
        PrintEthernetHeader(packet);
        packet += 14;
        PrintIPHeader(packet);
        tlen = (IPH*)packet;
        lengh = htons(tlen->len) - (uint16_t)(tlen->ihl) * 4;
        packet += (uint16_t)(tlen->ihl) * 4;
        PrintTCPHeader(packet);
        packet += (u_char)lengh;
    }

    pcap_close(handle);
    return 0;
}