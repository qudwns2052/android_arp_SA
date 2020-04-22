#ifndef INTERFACE_H
#define INTERFACE_H

#include "include.h"

class Interface
{
public:
    char intfName[20];
    volatile bool onThread;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t packet[50];

    Interface(char *intfName, uint8_t *packet)
    {
        memcpy(this->intfName, intfName, 20);
        onThread = false;
        handle = NULL;
        memcpy(this->packet, packet, 50);
    }

    void startThread(void);
    void stopThread(void);
    void arpAttack(void);

};

#endif // INTERFACE_H