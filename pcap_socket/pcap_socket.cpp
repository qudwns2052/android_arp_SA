#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <pcap.h>
#include <sys/select.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include "arp.h"

#define BUF_SIZE 1024

int server_fd, client_fd; // global varible. because close in signal_handler

void signal_handler(int signo) // signal handler
{
    close(server_fd);
    close(client_fd);
    printf("Bye bye~\n");
    exit(0);
}

void error_handler(void)
{
    close(server_fd);
    close(client_fd);
    exit(1);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    char buf[BUF_SIZE];
    char message[BUF_SIZE];
    char data[BUF_SIZE];

    struct sockaddr_in server_addr, client_addr; // socket address

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *all;
    pcap_if_t *temp;

    socklen_t addr_size = sizeof(client_addr);

    uint16_t server_port = 25164;   // set server port
    time_t start_time = time(NULL); // start start_time
    time_t current_time, run_time;

    int read_size;

    int option = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) // make server socket
    {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)); // set reuse

    memset(&server_addr, 0x00, sizeof(server_addr));

    // set server addr family, address, port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) // bind
    {
        fprintf(stderr, "%s\n", strerror(errno));
        close(server_fd);
        exit(1);
    }

    if (listen(server_fd, 5) < 0) // listen
    {
        fprintf(stderr, "%s\n", strerror(errno));
        close(server_fd);
        exit(1);
    }

    printf("wait...\n");

    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size)) < 0) // accept
    {
        close(server_fd);
        exit(1);
    }

    printf("connect ok\n");

    while (1)
    {

        memset(buf, 0x00, sizeof(buf));
        memset(data, 0x00, sizeof(data));

        if ((read_size = read(client_fd, buf, BUF_SIZE)) < 0) // recv data
            error_handler();

        if (read_size == 0) // if read size is 0, break
            error_handler();

        printf("read = %s size = %d\n", buf, strlen(buf));

        if (strcmp(buf, "1") == 0)
        {
            if (pcap_findalldevs(&all, error) == -1)
            {
                printf("error in pcap_findalldevs(%s)\n", error);
                return -1;
            }

            for (temp = all; temp; temp = temp->next)
            {
                strcat(temp->name, ",");
                strcat(data, temp->name);
            }
        }
        else
        {
            uint8_t subnet[4];
            uint8_t ip[4];
            uint8_t mac[6];

            char dev[10];
            strcpy(dev, buf);
            printf("buf = %s\ndev = %s\n", buf, dev);

            get_my_info(buf, subnet, ip, mac);

            char subnet_str[BUF_SIZE];
            char ip_str[BUF_SIZE];
            char mac_str[BUF_SIZE];

            sprintf(subnet_str, "%d.%d.%d.%d", subnet[0], subnet[1], subnet[2], subnet[3]);
            sprintf(ip_str, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            printf("subnet = %s\n", subnet_str);
            printf("ip = %s\n", ip_str);
            printf("mac = %s\n", mac_str);

            Arp * arp = new Arp();

            arp->setArp(dev);
            
            for (int i=0; i<10; i++)
            {
                arp->sendArp();
                printf("send arp...\n");
                sleep(1);
            }
            

            delete(arp);


            continue;
        }

        if (write(client_fd, data, strlen(data)) < 0) // send data
            error_handler();

        printf("wire ok \n\n");
    }

    close(client_fd); // close client_fd

    close(server_fd); // close server_fd

    return 0;
}
