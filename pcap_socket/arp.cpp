#include "arp.h"

void Arp::setArp(char * dev)
{
    struct ether_header *eth_rep = (struct ether_header *)(packet);
    struct arp_header *arp_rep = (struct arp_header *)(packet + ETH_HEADER_SIZE);

    strcpy(this->dev, dev);

    uint8_t my_mac[6];
    uint8_t my_ip[4];

    uint8_t ap_ip[4];
    uint8_t subnet[4];

    char notuse[20];

    printf("get my info \n");

    get_my_info(dev, subnet, my_ip, my_mac);

    memcpy(ap_ip, my_ip, 4);

    for (int i = 0; i < 4; i++)
        ap_ip[i] = ap_ip[i] & subnet[i];

    ap_ip[3] += 0b1;

    memset(eth_rep->ether_dhost, 0xff, 6);
    memcpy(eth_rep->ether_shost, my_mac, 6);
    eth_rep->ether_type = htons(ETHERTYPE_ARP);

    arp_rep->hw_type = htons(0x0001);
    arp_rep->proto_type = htons(0x0800);
    arp_rep->hlen = 0x06;
    arp_rep->plen = 0x04;
    arp_rep->oper = htons(0x0002);

    memcpy(arp_rep->smac, my_mac, 6);
    memcpy(arp_rep->sip, ap_ip, 4);
    memset(arp_rep->dmac, 0xff, 6);
    memset(arp_rep->dip, 0x00, 4);

    free(eth_rep);
    free(arp_rep);

    //packet이 자꾸 침범당해서, result로 옮겨놓음.... 안드로이드에서만 계속 값 오버라이팅 됨
    memcpy(result, packet, 50);

    printf("set arp OK\n");
}
void Arp::sendArp()
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        return;
    }

    pcap_sendpacket(handle, result, ETH_HEADER_SIZE + ARP_HEADER_SIZE);
    pcap_close(handle);

    // 패킷 값 변조 확인
    // for (int i = 0; i < ETH_HEADER_SIZE + ARP_HEADER_SIZE; i++)
    // {
    //     if (i % 16 == 0)
    //         printf("\n");
    //     printf("%02x ", result[i]);
    // }

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
