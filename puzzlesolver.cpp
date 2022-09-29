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
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <string.h>
#include <sstream>






struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

void make_socket_address(sockaddr_in *address, int port, std::string ip_address)
{
    sockaddr_in *socket_address = (sockaddr_in *)address;
    socket_address->sin_family = AF_INET;
    socket_address->sin_port = htons(port);
    socket_address->sin_addr.s_addr = inet_addr(ip_address.c_str());
}

std::string slice_secret_string(std::string secret_string)
{
    std::string ret_string = "";
    for(int i = 0; i < secret_string.length(); i++)
    {
        if(secret_string[i-1] == '"')
        {
            for(int j = i; j < secret_string.length(); j++)
            {
                if(secret_string[j] == '"')
                {
                    break;
                }
                ret_string += secret_string[j];
            }
        }

    }
    return ret_string;
}

//this function is from the the link given in the assignment on canvas
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return answer;
}

std::string solve_checksum(int port,std::string spoof_ip,int checksum,char* dest_ip){
    std::cout << "\nSOLVING CHECKSUM: " << std::endl;


    int checksum_netork_order = htons(checksum);


    char buffer[4096];
    std::string recvmsg;
    //create raw socekt
    int raw_david = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(raw_david == -1){perror("Failed to create raw socket"); exit(1);}

	//Datagram to represent the packet
	char datagram[1024] , source_ip[32] , *data , *pseudogram;
        //IP header
	struct ip *iph = (struct ip *) datagram;
    
    //UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;
	struct pseudo_header psh;

    //Monte Carlo Method
    for(int i = 0; i < 65535; i++){
        //zero out the packet buffer
        memset(datagram, 0, 1024);


        //Data part
        data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
        strcpy(data , "nori");

        //some address resolution
        strcpy(source_ip , spoof_ip.c_str());
        
        make_socket_address(&sin,port,dest_ip);

        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen(data));
        iph->ip_id = htons (54321);	//Id of this packet
        iph->ip_off = 0;	
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_sum = 0;		//Set to 0 before calculating checksum
        iph->ip_src.s_addr = inet_addr(source_ip); 	//Spoof the source ip address
        iph->ip_dst.s_addr =  sin.sin_addr.s_addr;

        iph->ip_sum = csum ((unsigned short *) datagram, sizeof(struct ip));

        //UDP header        
        udph->uh_sport = htons (i); //change the source port of i to try and get the correct checksum
        udph->uh_dport = htons (port);
        udph->uh_ulen = htons(8 + strlen(data));	//udp header size
        udph->uh_sum = 0;	//leave checksum 0 now, filled later by pseudo header

        psh.source_address = inet_addr(source_ip); //set ip as checksum ip provided 
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_UDP;
        psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

        int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
        pseudogram = (char*)malloc(psize);
        
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
        
        udph->uh_sum = csum( (unsigned short*) pseudogram , psize);
        
        if(udph->uh_sum == checksum_netork_order){
            break;
        }
    }


    // IP_HDRINCL to tell the kernel that headers are included in the packet 
    int optVal = 1;
    int status;
    status = setsockopt(raw_david, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal));
    if (status != 0) {
        perror("Can't set IP_HDRINCL option on a socket");
    }

    //Wrap the IPV4 packet in a UDP packet
    int socket_fd;
    struct sockaddr_in address;    
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    make_socket_address(&address, port, dest_ip);

    struct timeval read_timeout;
    read_timeout.tv_sec = 1;
    read_timeout.tv_usec = 50000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    socklen_t len = sizeof(address);
    while (recvmsg[0] != 'C'){
        sendto(socket_fd,datagram,32,0,(struct sockaddr *)&address,sizeof(address));

        int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

        if(nread > 0)
        {
            //get a list of responses from the server
            std:: cout << "from " << inet_ntoa(sin.sin_addr) << " port " << ntohs(sin.sin_port) << ": " << buffer << std:: endl;
            recvmsg = buffer;
        }
        else
        {
            std::cout << "Failed to receive from checksum port!" <<std::endl;
        }
        memset(buffer, 0, sizeof(buffer));
    }
    close(raw_david);

    return slice_secret_string(recvmsg);

}


std::string solve_evil_bit(int port,char* dest_ip){
    std::cout << "\nSOLVING EVIL BIT:" << std::endl;

    // To receive the response
    int socket_fd;
    struct sockaddr_in address;    
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    make_socket_address(&address, port, dest_ip);

    connect(socket_fd,(sockaddr*) &address,sizeof(address));
    socklen_t addrlen = sizeof(address);
    getsockname(socket_fd,(sockaddr*) &address,&addrlen);

    
    // Now there are many possibilities. You could do it this way
    // - create UDP socket
    // - call connect(130.208.242.120, 4099) on the socket fd
    // - call getsockname on the socket fd to get local IP and port, i.e. 192.168.191.17 and 54315
    // Use this as source for the RAW socket IP/UDP header
    // So if it is this what you are doing, it is fine. I guess this would be the simplest possibility.

    char buffer[4096];
    std::string recvmsg;
    //create raw socekt
    int raw_david = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(raw_david == -1){perror("Failed to create raw socket"); exit(1);}

	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;

	//zero out the packet buffer
	memset (datagram, 0, 4096);

    //IP header
	struct ip *iph = (struct ip *) datagram;
    
    //UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

    struct sockaddr_in sin;
	struct pseudo_header psh;
    //Data part
	data = datagram + sizeof(struct ip) + sizeof(struct udphdr);
	strcpy(data , "$group_16$");

    //some address resolution
	// strcpy(source_ip , "ding");
    //copy the ip addr of address to source_ip
    inet_ntop(AF_INET, &address.sin_addr, source_ip, sizeof(source_ip));
    
    make_socket_address(&sin,port,dest_ip);
    struct in_addr meow;
    meow.s_addr = inet_addr(source_ip);

    iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sizeof (struct ip) + sizeof (struct udphdr) + strlen(data);
	iph->ip_id = htons (543210);	//Id of this packet
	iph->ip_off = IP_RF;	//SET EVIL BIT
	iph->ip_ttl = 255;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_sum = 0;		//Set to 0 before calculating checksum
	iph->ip_src = address.sin_addr; 	//Spoof the source ip address
	iph->ip_dst =  sin.sin_addr;

    //UDP header

	iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len);
    
	udph->uh_sport = address.sin_port;
	udph->uh_dport = htons (port);
	udph->uh_ulen = htons(8 + strlen(data));	//udp header size
	udph->uh_sum = 0;	//leave checksum 0 now, filled later by pseudo header

    psh.source_address = inet_addr(source_ip); //set ip 
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	pseudogram = (char*)malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	// udph->uh_sum = csum( (unsigned short*) pseudogram , psize);

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int optVal = 1;
    int status;
    status = setsockopt(raw_david, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal));
    if (status != 0) {
        perror("Can't set IP_HDRINCL option on a socket");
    }
    while (recvmsg[0] != 'Y'){
        sendto(raw_david, datagram, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin));

        struct timeval read_timeout;
        read_timeout.tv_sec = 1;
        read_timeout.tv_usec = 50000;
        int time_status = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        if (time_status != 0) {
            perror("Can't set timeout option on a socket");
        }

        socklen_t len = sizeof(socket_fd);
        if(recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len) < 0){
            perror("Failed to receive from port in evil bit, trying again");
        }
        recvmsg = buffer;
    }
    std:: cout << "from " << inet_ntoa(sin.sin_addr) << " port " << ntohs(sin.sin_port) << ": " << buffer << std:: endl;
    //return the last 4 characters of the response which is the port number
    return recvmsg.substr(recvmsg.length()-4);
}


std::string get_spoof_ip(std::string message){
    std::string spoof_ip;

    //ip address always starts at 186 but it can be shorter than 14.
    for(int i = 186; i <= 200; i++) 
    { 
        if (message[i] != '!') // if the character is a ! we know that it is shorter than 14
        {
            spoof_ip += message[i];
        }
        if (message[i] == '!') 
        { 
            break;
        }
    }
    return spoof_ip;
}

long get_checksum(std::string message){
    std::string checksum;
    for(int i = 144; i <= 149; i++) 
    { 
        checksum += message[i];
    }

    long l = strtol(checksum.c_str(), nullptr, 16);

    return l;
}


std::string get_first_port(std::string message){
    std::string port;
    port = message.substr(58,4);
    return port;
}

std::string solve_oracle(std::string port1, std::string &port2,int port, char* ip){
    std::cout << "\nSOLVING ORACLE:\n";
    int socket_fd;
    struct sockaddr_in address;
    //TODO:make the hardcoded string with the secret ports here insteead of gigaloop
    std:: string sentmsg = port1 + "," + port2;
    char buffer[8192];
    std::string recvmsg;

    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
    }

    
    // Set the address
    make_socket_address(&address, port, ip);

    //set timeout so recv doesnt halt forever on non responding ports
    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 50000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    //send to each port a
    while (recvmsg[0] != '4'){
        sendto(socket_fd,sentmsg.c_str(),sizeof(sentmsg) - 1,0,(struct sockaddr *)&address,sizeof(address));
        
        
        socklen_t len = sizeof(address);
        int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

        if(nread > 0)
        {
            if (buffer[0] != 'I'){
                std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << ": " << buffer << std:: endl;
                recvmsg = buffer;
            }
        }
        memset(buffer, 0, sizeof(buffer));
    }
    close(socket_fd);

    return recvmsg;
}

//NOTE: use the scanner to find the open ports and then use them as args for the puzzle solver

//Take a reference to a socket address and connect it to the given ip and port



std::vector<std::string> send_to_open(char *ip, int port1, int port2, int port3, int port4)
{
    int socket_fd;
    struct sockaddr_in address;
    int i;
    int open_ports[] = {port1, port2, port3, port4};
    std:: string sentmsg = "$group_16$";
    char buffer[8192];
    std::vector<std::string> recv_vec;
    std::string recvmsg;
    
    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
    }


    // code in loop gets the messages from the server and sends them back
    for (i = 0; i < 4; i++)
    {
        // Set the address
        make_socket_address(&address, open_ports[i], ip);

        //set timeout so recv doesnt halt forever on non responding ports
        struct timeval read_timeout;
        read_timeout.tv_sec = 1;
        read_timeout.tv_usec = 50000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        //send to each port a
        while (true){
            sendto(socket_fd,sentmsg.c_str(),sizeof(sentmsg) - 1,0,(struct sockaddr *)&address,sizeof(address));
            socklen_t len = sizeof(address);
            int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 
            if(buffer[0] == 'R'){
                std::cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << ": " << buffer << ". Trying again" << std:: endl;
            }
            if(nread > 0 && buffer[0] != 'R')
            {
                //get a list of responses from the server
                recvmsg = buffer;
                recv_vec.push_back(recvmsg);
                memset(buffer, 0, sizeof(buffer));
                break;
            }

            memset(buffer, 0, sizeof(buffer));
        }

    }
        close(socket_fd);


    return recv_vec;



}

std::string knock_knock(int secret_port1, int secret_port2,char* target_ip,std::string secret_message,std::vector<int> ports){
    //conducts the knocks in the order given by the oracle with the secret message as the payload
    std::cout << std::endl << "Knocking:" << std::endl;
    int socket_fd;
    struct sockaddr_in address;
    char buffer[8192];
    std::string recvmsg;

    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
    }
    while (recvmsg[0] != 'Y' && recvmsg[1] != 'o' && recvmsg[2] != 'u' && recvmsg[3] != ' ' && recvmsg[4] != 'h' && recvmsg[5] != 'a'){
    //send to each port in the knock pattern
        for(int i = 0; i < ports.size(); i++){

            make_socket_address(&address, ports[i], target_ip);
            struct timeval read_timeout;
            read_timeout.tv_sec = 0;
            read_timeout.tv_usec = 50000;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
            sendto(socket_fd,secret_message.c_str(),secret_message.size(),0,(struct sockaddr *)&address,sizeof(address));

            //finally recieve the final messgage
            socklen_t len = sizeof(address);

            int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr*)&address,&len);

            if(nread > 0)
            {
                std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << ": " << buffer << std:: endl;
                recvmsg = buffer;
            }
            memset(buffer, 0, sizeof(buffer));
            if (recvmsg[0] == 'Y' && recvmsg[1] == 'o' && recvmsg[2] == 'u' && recvmsg[3] == ' ' && recvmsg[4] == 'h' && recvmsg[5] == 'a'){
                break;
            }

        }
    }
    close(socket_fd);
    
    return recvmsg;

}


std::vector<int> parse_to_vector(std::string knock_pattern){
    //parses the knock pattern string to a vector of ints
    std::vector<int> vec;
    // std::stringstream ss(knock_pattern);
    std::string port;

    for (int i = 0; i < knock_pattern.size(); i++) {  
        if (knock_pattern[i] == ',' || (i == knock_pattern.size())){ //if comma, we have a complete port, restart the port string and add it to the vector
            int port_int = std::stoi(port,nullptr,10);
            vec.push_back(port_int);
            port = "";
        }
        else{ //else we build the string
            port += knock_pattern[i];  
        }
    }
    vec.push_back(std::stoi(port,nullptr,10)); //add the last port to the vector

    return vec;

}

int main(int argc, char *argv[])
{
    //Make sure serverIp and port(High low) are supplied
    if (argc != 6)
    {
        std::cout << "Usage ./client <serverIp> <port1> <port2> <port3> <port4>" << std::endl;
        exit(0);
    }
    char* target_IP = argv[1];
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    int port3 = atoi(argv[4]);
    int port4 = atoi(argv[5]);



    std::cout << "Solving with ports " << port1 << ", " << port2 << ", " << port3 << ", " << port4 << " on " << target_IP << std::endl<< std::endl;
    int open_ports[] = {port1, port2, port3, port4};

    //returns a vector of the messages from server
    std::vector<std::string> msg_list;
    while (msg_list.size() < 4){
        msg_list = send_to_open(target_IP, port1, port2, port3, port4);
    }
    for(int i = 0; i < msg_list.size(); i++){
        std:: cout << "from " << target_IP << " port " << open_ports[i] << ": " << msg_list[i] << std:: endl;
    }
                
    std::string spoof_ip;

    //checksum base 10
    long checksum;
    std::string secret_port1;
    std::string secret_port2;
    std::string secret_phrase;
    std::string knock_pattern;

    int oracle_port;

    for(int i = 0; i < msg_list.size(); i++){

        // checksum solver, check if message starts with h (Hello, group16!)
        
        if(msg_list[i][0] == 'H'){
            spoof_ip = get_spoof_ip(msg_list[i]);
            checksum = get_checksum(msg_list[i]);
            //TODO: solve checksum part
            secret_phrase = solve_checksum(open_ports[i],spoof_ip,checksum,target_IP);
        }
        if(msg_list[i][0] == 'M'){
            secret_port1 =  get_first_port(msg_list[i]);
        }
        //solve oracle
        if(msg_list[i][0] == 'I'){
            oracle_port = open_ports[i];
        }      
        if(msg_list[i][0] == 'T'){
            secret_port2 = solve_evil_bit(open_ports[i],target_IP);
        }
    }

    knock_pattern = solve_oracle(secret_port1,secret_port2,oracle_port,target_IP);
    
    std::vector<int> knock_pattern_vector = parse_to_vector(knock_pattern);

    // conduct the knocks.
    std::cout << secret_port1 << " " << secret_port2 << std::endl;
    int secret_port1_int = std::stoi(secret_port1,nullptr,10);
    int secret_port2_int = std::stoi(secret_port2,nullptr,10);
    // TODO: think it works, but perhaps the phrase is wrong
    std::string final_message = knock_knock(secret_port1_int,secret_port2_int,target_IP,secret_phrase,knock_pattern_vector);

    std::cout << "Final message: " << final_message << std::endl;
}   

// 4021 4044 4071 4092