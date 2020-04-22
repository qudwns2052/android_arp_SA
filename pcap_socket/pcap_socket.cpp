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


int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    char buf[BUF_SIZE];
    char data[BUF_SIZE];
    struct sockaddr_in server_addr, client_addr; // socket address
    socklen_t addr_size = sizeof(client_addr);
    uint16_t server_port = 25164;   // set server port
    int read_size;
    int option = 1;

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *all;
    pcap_if_t *temp;

    std::list<Interface> intfList;



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

    Arp * arp = new Arp;

    while (1)
    {
    
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

            if ((read_size = read(client_fd, buf, BUF_SIZE)) <= 0) // recv data
                error_handler();

            if (strcmp(buf, "1") == 0)
            {
                if (pcap_findalldevs(&all, error) == -1)
                {
                    printf("error in pcap_findalldevs(%s)\n", error);
                    return -1;
                }

                memset(data, 0x00, sizeof(data));

                for (temp = all; temp; temp = temp->next)
                {
                    strcat(temp->name, ",");
                    strcat(data, temp->name);
                }

                if (write(client_fd, data, strlen(data)) < 0) // send data
                    error_handler();

                printf("send interface list\n");
            }
            else if (strcmp(buf, "2") == 0)
            {
                break;
            }
            else
            {
                std::list<Interface>::iterator iter = intfList.begin();

                while(iter != intfList.end())
                {
                    if(strcmp(iter->intfName, buf) == 0)
                        break;
                    iter++;
                }


                if(iter != intfList.end())
                {
                    printf("find (interface = %s)\n", iter->intfName);
                    if(iter->onThread == true)
                        iter->stopThread();
                    else
                        iter->startThread();
                }
                else
                {
                    printf("append Interface class (interface = %s)\n", buf);
                    arp->setArp(buf);
                    intfList.push_back(Interface(buf, arp->result));
                    intfList.back().startThread();
                }
            }
        }
        close(client_fd); // close client_fd
    }

    delete arp;
    close(server_fd); // close server_fd

    return 0;
}
