typedef int SOCKET_TYPE;
typedef unsigned int ADDRESS_SIZE;
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <vector>
#include <set>


//Take a reference to a socket address and connect it to the given ip and port
void make_socket_address(sockaddr_in *address, int port, std::string ip_address)
{
    sockaddr_in *socket_address = (sockaddr_in *)address;
    socket_address->sin_family = AF_INET;
    socket_address->sin_port = htons(port);
    socket_address->sin_addr.s_addr = inet_addr(ip_address.c_str());
}


int scan_ports(char *ip, int low, int high)
{
    int socket_fd;
    struct sockaddr_in address;
    int port;
    int result;
    int i;
    int count = 0;
    std::set<int> open_ports;
    std:: string sentmsg = "Hello World";
    char buffer[4096];
    
    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
        return -1;
    }

    while (open_ports.size() < 4) {
        for (i = low; i <= high; i++)
        {

            // Set the address
            make_socket_address(&address, i, ip);

            //set timeout so recv doesnt halt forever on non responding ports
            struct timeval read_timeout;
            read_timeout.tv_sec = 0;
            read_timeout.tv_usec = 50000;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));


            sendto(socket_fd,"HelloWorld",sizeof("HelloWorld") - 1,0,(struct sockaddr *)&address,sizeof(address));

            socklen_t len = sizeof(address);
            int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

        
            if(nread > 0)
            {
                open_ports.insert(ntohs(address.sin_port));
            }
            memset(buffer, 0, sizeof(buffer));


        }
    }
    close(socket_fd);
    std::set<int>::iterator itr;
    for(itr = open_ports.begin(); itr != open_ports.end(); itr++)
    {
        std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << *itr << " is open " << std:: endl;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    //Make sure serverIp and port(High low) are supplied
    if (argc != 4)
    {
        std::cout << "Usage ./client <serverIp> <portLow> <portHigh>" << std::endl;
        exit(0);
    }
    char* target_IP = argv[1];
    int low_port = atoi(argv[2]);
    int high_port = atoi(argv[3]);

    std::cout << "Scanning ports " << low_port << " to " << high_port << " on " << target_IP << std::endl;

    scan_ports(target_IP, low_port, high_port);
}