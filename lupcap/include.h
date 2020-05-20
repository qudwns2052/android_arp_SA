#ifndef INCLUDE_H
#define INCLUDE_H

#include <algorithm>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <iostream>
#include <list>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <thread>
#include <unistd.h>

#include "arp.h"
#include "interface.h"

#define ETH_HEADER_SIZE 14
#define ARP_HEADER_SIZE 28
#define BUF_SIZE 1024

#endif // INCLUDE_H
