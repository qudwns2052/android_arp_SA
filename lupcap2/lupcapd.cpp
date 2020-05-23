#include "lupcapd.h"

bool lupcap_close(pcap_t *handle)
{
    if (handle == NULL)
    {
        return false;
    }
    else
    {
        pcap_close(handle);
        printf("[+] pcap close success\n");
        return true;
    }
}

bool lupcap_findalldevs(uint8_t *data)
{
    
    pcap_if_t *alldevs;
    pcap_if_t *temp;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("[-] pcap_findalldevs failed\n");
        return false;
    }

    for (temp = alldevs; temp; temp = temp->next)
    {
        strcat((char *)data, temp->name);
        strcat((char *)data, "+");
    }
    printf("[+] pcap_findalldevs success\n");

    return true;
}

bool lupcap_read(pcap_t *handle, uint8_t *data)
{
    struct pcap_pkthdr *header;
    const u_char * temp;

    while (true)
    {
        int res = pcap_next_ex(handle, &header, &temp);
        if (res == -1 || res == -2)
        {
            printf("[-] pcap next_ex failed\n");
            return false;
        }

    }

    memcpy(data, temp, strlen((char *)temp));

    printf("[+] pcap next_ex success\n");

    return true;
}

bool lupcap_write(pcap_t *handle, uint8_t *data)
{
    int dataLength = (int)strlen((char *)data);
    if (pcap_sendpacket(handle, data, dataLength) != 0)
    {
        printf("[-] pcap_sendpacket failed\n");
        return false;
    }
    printf("[+] pcap_sendpacket success\n");
    return true;
}
