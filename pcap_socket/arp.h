#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETH_HEADER_SIZE 14
#define ARP_HEADER_SIZE 28
/* ARP header */
struct arp_header
{
    uint16_t hw_type;    /* Hardware Type           */
    uint16_t proto_type; /* Protocol Type           */
    uint8_t hlen;        /* Hardware Address Length */
    uint8_t plen;        /* Protocol Address Length */
    uint16_t oper;       /* Operation Code          */
    uint8_t smac[6];     /* Sender hardware address */
    uint8_t sip[4];      /* Sender IP address       */
    uint8_t dmac[6];     /* Target hardware address */
    uint8_t dip[4];      /* Target IP address       */
};

struct info
{
    // QString name_;
    // QString desc_;
    pcap_if_t *dev_{nullptr};
    uint8_t mac_;
    uint32_t ip_;
    uint32_t mask_;
    uint32_t gateway_;
    uint32_t ip_and_mask_;
};

class Arp
{
public:
    uint8_t packet[50];
    uint8_t result[50];
    char dev[20];
    Arp()
    {
        memset(packet, 0x00, 50);
        memset(dev, 0x00, 20);
    }
    ~Arp()
    {

    }

    void setArp(char * dev);
    void sendArp();
};

void get_my_info(char *dev, uint8_t *subnet, uint8_t *ip, uint8_t *mac);
#endif // ARP_H
