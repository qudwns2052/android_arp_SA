#ifndef ARP_H
#define ARP_H

#include "include.h"

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

class Arp
{
public:
    uint8_t packet[50];
    uint8_t request_packet[50];
    uint8_t recover_packet[50];
    uint8_t attack_packet[50];

    char dev[20];
    Arp()
    {
        memset(packet, 0x00, 50);
        memset(dev, 0x00, 20);
    }
    ~Arp()
    {
    }

    void setArp(char *dev);
    void getGatewayMac(uint8_t * my_mac, uint8_t *gateway_mac);
};

bool check_dev(char *dev);
void get_my_info(char *dev, uint8_t *subnet, uint8_t *ip, uint8_t *mac);
#endif // ARP_H
