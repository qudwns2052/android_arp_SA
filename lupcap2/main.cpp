#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "lupcapd.h"

#define SEND_SIZE 1024

using namespace std;

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t addr_size = sizeof(client_addr);
    uint16_t server_port = 25164; // set server port
    int option = 1;

    uint8_t type[2];
    uint8_t data[SEND_SIZE];
    uint8_t save_data[SEND_SIZE];
    char recv_data[SEND_SIZE];
    char dev[10];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) // make server socket
    {
        return 0;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)); // set reuse

    // set server addr family, address, port
    memset(&server_addr, 0x00, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) // bind
    {
        return 0;
    }

    if (listen(server_fd, 5) < 0) // listen
    {
        return 0;
    }

    printf("accept wait...\n");

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);

    if (client_fd < 0)
    {
        close(server_fd);
        exit(1);
    }

    printf("[*] connection success\n");

    pcap_t *handle;
    pcap_pkthdr *header;
    bool ret_check;
    int read_size;
    int dataLength;

    while (1)
    {
        printf("[+] waiting...\n");
        memset(recv_data, 0, sizeof(recv_data));
        memset(data, 0, sizeof(data));
        memset(save_data, 0, sizeof(save_data));

        printf("@@@@@@@@@@@@@@@\n");

        if ((read_size = read(client_fd, recv_data, sizeof(recv_data))) <= 0) // recv data
        {
            printf("[-] recv failed\n");
            continue;
        }

        printf("read size = %d\n", read_size);

        for (int i = 0; i < read_size; i++)
        {
            printf("%d ", recv_data[i]);
        }
        printf("\n");

        memcpy(type, recv_data, sizeof(type));

        if (type[1] == 0x11)
        {
            memcpy(dev, recv_data + 3, read_size - 3);
            
            printf("dev = %s\n", dev);

            char errbuf[PCAP_ERRBUF_SIZE];

            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL)
            {
                printf("[-] pcap handle failed\n");
                ret_check = false;
            }
            else
            {
                printf("[+] pcap handle success\n");
                ret_check = true;
            }
        }
        else if (type[1] == 0x12)
        {
            ret_check = lupcap_close(handle);
            break;
        }
        else if (type[1] == 0x13)
        {
            ret_check = lupcap_findalldevs(save_data);
        }
        else if (type[1] == 0x14)
        {
            ret_check = lupcap_read(handle, save_data);
        }
        else if (type[1] == 0x15)
        {
            ret_check = lupcap_write(handle, (uint8_t *)recv_data + 3);
        }
        else
        {
            printf("%s is what??\n", recv_data);
            continue;
        }

        memcpy(data, type, sizeof(type));
        strcat((char *)data, " ");

        if (ret_check == 0)
        {
            data[sizeof(type) + 1] = 0x00;
        }
        else
        {
            data[sizeof(type) + 1] = 0x01;
            if ((type[1] == 0x13) || (type[1] == 0x14))
            {
                dataLength = strlen((char *)save_data);
                char dataLength_str[10];
                sprintf(dataLength_str, "%d", dataLength);
                printf("len = %s\n", dataLength_str);
                strcat((char *)data, " ");
                strcat((char *)data, dataLength_str);
                strcat((char *)data, " ");
                strcat((char *)data, (char *)save_data);
            }
        }
        write(client_fd, data, strlen((char*)data)); // send data

    }
    close(client_fd);
    close(server_fd);
}
