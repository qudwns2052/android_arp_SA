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
        if(pcap_sendpacket(handle, packet, ETH_HEADER_SIZE + ARP_HEADER_SIZE)!=0)
        {
            printf("error\n");
        }
        printf("%s\n", this->intfName);

        std::this_thread::sleep_for(std::chrono::duration<int>(1));
        printf("send arp...\n");
    }

    printf("thread stop (interface = %s)\n", intfName);

    pcap_close(handle);
}
