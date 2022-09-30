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

//Take a reference to a socket address and connect it to the given ip and port
void make_socket_address(sockaddr_in *address, int port, std::string ip_address)
{
    sockaddr_in *socket_address = (sockaddr_in *)address;
    socket_address->sin_family = AF_INET;
    socket_address->sin_port = htons(port);
    socket_address->sin_addr.s_addr = inet_addr(ip_address.c_str());
}

std::set<int> scan_ports(char *ip, int low, int high)
{
    //Creates a datagram socket and scans all the ports in the range low to high and returns a set of open the open ports
    int socket_fd;
    struct sockaddr_in address;
    int port;
    int result;
    int i;
    int count = 0;
    //use a set to get rid of duplicates
    std::set<int> open_ports;
    std:: string sentmsg = "Hello World";
    char buffer[4096];
    
    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
        exit(-1);
    }

    while (open_ports.size() < 4) { //we know there are 4 open ports
        for (i = low; i <= high; i++)//scan all the ports
        {
            // Set the address
            make_socket_address(&address, i, ip);

            //set timeout so recv doesnt halt forever on non responding ports
            struct timeval read_timeout;
            read_timeout.tv_sec = 0;
            read_timeout.tv_usec = 50000;
            setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

            //send a message to the port
            sendto(socket_fd,"HelloWorld",sizeof("HelloWorld") - 1,0,(struct sockaddr *)&address,sizeof(address));

            socklen_t len = sizeof(address);
            //receive a response from the port
            int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

            //if we get a response, add the port to the set
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
        std::cout << "from " << inet_ntoa(address.sin_addr) << " port " << *itr << " is open " << std:: endl;
    }

    return open_ports;
}

std::string slice_secret_string(std::string secret_string)
{
    //Extracts the secret phrase from the string
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
    //Calculates checksum
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
        //break if our calculated checksum matches the wanted checksum
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

    //set timeout so recv doesnt halt forever on non responding ports
    struct timeval read_timeout;
    read_timeout.tv_sec = 1;
    read_timeout.tv_usec = 500000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    socklen_t len = sizeof(address);
    //Send the packet to server and receive the response, retry if packet is lost/dropped/recieve fails
    while (recvmsg[0] != 'C'){//C for Congratulations...
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
    // return only the secret phrase
    return slice_secret_string(recvmsg);

}


std::string solve_evil_bit(int port,char* dest_ip){
    std::cout << "\nSOLVING EVIL BIT:" << std::endl;

    int socket_fd;
    struct sockaddr_in address;    
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    make_socket_address(&address, port, dest_ip);

    connect(socket_fd,(sockaddr*) &address,sizeof(address));
    socklen_t addrlen = sizeof(address);
    getsockname(socket_fd,(sockaddr*) &address,&addrlen);

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

    inet_ntop(AF_INET, &address.sin_addr, source_ip, sizeof(source_ip));
    
    make_socket_address(&sin,port,dest_ip);

    //Build the IP header
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

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int optVal = 1;
    int status;
    status = setsockopt(raw_david, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal));
    if (status != 0) {
        perror("Can't set IP_HDRINCL option on a socket");
    }
    //send the packet to the server and retry if the response is not correct
    while (recvmsg[0] != 'Y'){ //Y for Yes, strong in the dark side...
        sendto(raw_david, datagram, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin));

        //set timeout so recv doesnt halt forever on non responding ports
        struct timeval read_timeout;
        read_timeout.tv_sec = 1;
        read_timeout.tv_usec = 500000;
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
    // get the ip address from the message from server
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
    //get the desired checksum from the message from server
    std::string checksum;
    for(int i = 144; i <= 149; i++) 
    { 
        checksum += message[i];
    }

    long l = strtol(checksum.c_str(), nullptr, 16);

    return l;
}


std::string get_first_port(std::string message){
    // Get the free secret port, its always at the same place
    std::string port;
    port = message.substr(58,4);
    return port;
}

std::string solve_oracle(std::string port1, std::string &port2,int port, char* ip){
    std::cout << "\nSOLVING ORACLE:\n";
    int socket_fd;
    struct sockaddr_in address;
    std::string sentmsg = port1 + "," + port2;
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
    read_timeout.tv_usec = 500000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    //send the port string to the oracle and receive the secret phrase
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

std::vector<std::string> send_to_open(char *ip, std::vector<int> open_ports)
{
    //Sends a message to each open port and return a vector of the responses
    int socket_fd;
    struct sockaddr_in address;
    int i;
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
    for (i = 0; i < open_ports.size(); i++)
    {
        // Set the address
        make_socket_address(&address, open_ports[i], ip);

        //set timeout so recv doesnt halt forever on non responding ports
        struct timeval read_timeout;
        read_timeout.tv_sec = 1;
        read_timeout.tv_usec = 500000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        //send to each port and retry if server doesnt respond
        while (true){
            sendto(socket_fd,sentmsg.c_str(),sizeof(sentmsg) - 1,0,(struct sockaddr *)&address,sizeof(address));
            socklen_t len = sizeof(address);
            int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 
            if(buffer[0] == 'R'){
                std::cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << ": " << buffer << ". Trying again" << std:: endl;
            }
            if(nread > 0 && buffer[0] != 'R')//R for random checksum collision
            {
                // take response from the server and add it to the vector
                recvmsg = buffer;
                recv_vec.push_back(recvmsg);
                memset(buffer, 0, sizeof(buffer));
                break;
            }
            //reset the buffer
            memset(buffer, 0, sizeof(buffer));
        }
    }
    close(socket_fd);
    return recv_vec;
}

std::string knock_knock(int secret_port1, int secret_port2,char* target_ip,std::string secret_message,std::vector<int> ports){
    //conducts the knocks in the order given by the oracle with the secret message as the payload
    int socket_fd;
    int nread = -1;
    struct sockaddr_in address;
    char buffer[8192];
    std::string recvmsg;

    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
    }
    
    //send to each port in the knock pattern, retrying if the server doesnt respond
    std::cout << std::endl << "Knocking:" << std::endl;
    for(int i = 0; i < ports.size(); i++){
        make_socket_address(&address, ports[i], target_ip);
        struct timeval read_timeout;
        read_timeout.tv_sec = 0;
        read_timeout.tv_usec = 500000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        while(nread == -1){
            sendto(socket_fd,secret_message.c_str(),secret_message.size(),0,(struct sockaddr *)&address,sizeof(address));

            socklen_t len = sizeof(address);

            nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr*)&address,&len);
            if (nread == -1){
                std::cout << "Knocking failed, trying again" << std::endl;
            }
            if(nread > 0)
            {
                std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << ": " << buffer << std:: endl;
                recvmsg = buffer;
            }
            memset(buffer, 0, sizeof(buffer));
        }
        nread = -1;
    }

    close(socket_fd);
    return recvmsg;

}


std::vector<int> parse_to_vector(std::string knock_pattern){
    //parses the knock pattern string to a vector of ints
    std::vector<int> vec;

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
    if (argc != 2)
    {
        std::cout << "Usage ./client <serverIp>" << std::endl;
        exit(0);
    }
    char* target_IP = argv[1];
    int low_port = 4000;
    int high_port = 4100;

    std::cout << "Scanning ports " << low_port << " to " << high_port << " on " << target_IP << std::endl;
    //Scan for the open ports and store them in a vector, the scanning function returns a set to avoid duplicates
    std::set<int> open_ports_set = scan_ports(target_IP, low_port, high_port);
    std::set<int>::iterator itr;
    std::vector<int> open_ports;
    std::cout << "Solving with ports ";
    for(itr = open_ports_set.begin(); itr != open_ports_set.end(); itr++)
    {
        std::cout << *itr << " , ";
        open_ports.push_back(*itr);
    }
    std::cout << "on " << target_IP << std::endl<< std::endl;

    //returns a vector of the messages from server
    std::vector<std::string> msg_list;
    while (msg_list.size() < 4){
        msg_list = send_to_open(target_IP, open_ports);
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

        // checksum solver, check if message starts with H (Hello, group16!)
        
        if(msg_list[i][0] == 'H'){
            spoof_ip = get_spoof_ip(msg_list[i]);
            checksum = get_checksum(msg_list[i]);
            //TODO: solve checksum part
            secret_phrase = solve_checksum(open_ports[i],spoof_ip,checksum,target_IP);
        }
        // Given port, check if message starts with M (My boss...)
        if(msg_list[i][0] == 'M'){
            secret_port1 =  get_first_port(msg_list[i]);
        }
        // set oracle port, check if message starts with I (I am the oracle...)
        if(msg_list[i][0] == 'I'){
            oracle_port = open_ports[i];
        }
        // Evil bit solver, check if message starts with T (The dark side...)
        if(msg_list[i][0] == 'T'){
            secret_port2 = solve_evil_bit(open_ports[i],target_IP);
        }
    }
    //solve oracle and get the knock pattern
    knock_pattern = solve_oracle(secret_port1,secret_port2,oracle_port,target_IP);
    
    std::vector<int> knock_pattern_vector = parse_to_vector(knock_pattern);

    // conduct the knocks.
    std::cout << secret_port1 << " " << secret_port2 << std::endl;
    int secret_port1_int = std::stoi(secret_port1,nullptr,10);
    int secret_port2_int = std::stoi(secret_port2,nullptr,10);
    std::string final_message = knock_knock(secret_port1_int,secret_port2_int,target_IP,secret_phrase,knock_pattern_vector);

    if(strstr(final_message.c_str(), "You have knocked. You may enter")){
        std::cout << "Success!" << std::endl;
    }
    else{
        std::cout << "Failure" << std::endl;
    }
}