#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

bool lupcap_close(pcap_t * handle);
bool lupcap_findalldevs(uint8_t * data);
bool lupcap_read(pcap_t * handle, uint8_t * data);
bool lupcap_write(pcap_t * handle, uint8_t * data);
