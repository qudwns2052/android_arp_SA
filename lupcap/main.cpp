#include "include.h"

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

bool lupcap_open(pcap_t *handle, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("pcap open error...\n");
        return false;
    }

    return true;
}

void lupcap_close(pcap_t *handle)
{
    pcap_close(handle);
}

bool lupcap_findalldevs(int *dataLength, char *data)
{
    pcap_if_t *all;
    pcap_if_t *temp;
    char error[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all, error) == -1)
    {
        return false;
    }

    for (temp = all; temp; temp = temp->next)
    {
        if (check_dev(temp->name))
        {
            strcat(temp->name, ",");
            strcat(data, temp->name);
        }
    }

    *dataLength = (int)strlen(data);

    // int length = (int)strlen(data);
    // memcpy(&length, dataLength, sizeof(int));

    return true;
}

bool lupcap_read(pcap_t *handle, int *dataLength, uint8_t *data)
{
    struct pcap_pkthdr *header;
    const u_char *temp;

    while (true)
    {
        int res = pcap_next_ex(handle, &header, &data);

        if (res == 0)
            continue;
        if (res == -1 || res == -2)
            return false;

        break;
    }

    *dataLength = (int)strlen((char *)data);

    return true;
}

bool lupcap_write(pcap_t *handle, int *dataLength, uint8_t *data)
{

    if (pcap_sendpacket(handle, data, *dataLength) != 0)
    {
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    char buf[BUF_SIZE];
    char data[BUF_SIZE];
    struct sockaddr_in server_addr, client_addr; // socket address
    socklen_t addr_size = sizeof(client_addr);
    uint16_t server_port = 25164; // set server port
    int read_size;
    int option = 1;

    char error[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) // make server socket
    {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(1);
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)); // set reuse

    // set server addr family, address, port
    memset(&server_addr, 0x00, sizeof(server_addr));
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

    printf("wait accept...\n");

    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size)) < 0) // accept
    {
        close(server_fd);
        exit(1);
    }

    printf("connection ok!\n");

    while (1)
    {
        memset(buf, 0x00, sizeof(buf));
        memset(data, 0x00, sizeof(data));
        int dataLength = 0;

        if ((read_size = read(client_fd, buf, BUF_SIZE)) <= 0) // recv data
            error_handler();

        // bool lupcap_open(pcap_t *handle, char *dev)
        if (!lupcap_open(handle, buf))
            break;

        // bool lupcap_close(void)
        
        lupcap_close(handle);

        // bool lupcap_findalldevs(int *dataLength, char *data)
        if (!lupcap_findalldevs(&dataLength, data))
            error_handler();
        printf("send interface list\n");

        //bool lupcap_read(pcap_t *handle, int *dataLength, uint8_t *data)
        if (!lupcap_read(handle, &dataLength, (uint8_t*)data))
            error_handler();
        //bool lupcap_write(pcap_t *handle, int *dataLength, uint8_t *data)
        if(!lupcap_write(handle, &dataLength, (uint8_t*)data))
            error_handler();



        if (write(client_fd, data, strlen(data)) < 0) // send data
            error_handler();
    }

    close(client_fd); // close client_fd
    close(server_fd); // close server_fd

    lupcap_close(handle);

    return 0;
}
