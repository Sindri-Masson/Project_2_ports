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
    std::cout << "Solving checksum - dest ip: " << dest_ip << std::endl;
    std::cout << "Solving checksum - dest port: " << port << std::endl;


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
	strcpy(data , "nori");

    //some address resolution
	strcpy(source_ip , source_ip);
    
    make_socket_address(&sin,4099,dest_ip);
    struct in_addr meow;
    meow.s_addr = inet_addr(source_ip);

    iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;
	iph->ip_len = sizeof (struct ip) + sizeof (struct udphdr) + strlen(data);
	iph->ip_id = htons (54321);	//Id of this packet
	iph->ip_off = 0;	//Þetta er pottþett eh evilbit drasl
	iph->ip_ttl = 255;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_sum = 0;		//Set to 0 before calculating checksum
	iph->ip_src = meow; 	//Spoof the source ip address
	iph->ip_dst =  sin.sin_addr;

    //UDP header

	iph->ip_sum = csum ((unsigned short *) datagram, iph->ip_len);
    
	udph->uh_sport = htons (6666);
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

    //IP_HDRINCL to tell the kernel that headers are included in the packet GOOOOOOOD YEEEES!
    int optVal = 1;
    int status;
    status = setsockopt(raw_david, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal));
    if (status != 0) {
        perror("Can't set IP_HDRINCL option on a socket");
    }

    int ding = sendto(raw_david, datagram, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin));
    std::cout << "ding " << ding << std::endl;
    // socklen_t len = sizeof(sin);
    // int nread = recvfrom(raw_david,buffer,sizeof(buffer),0,(struct sockaddr *)&sin,&len); 

    // if(nread > 0)
    // {
    //     //get a list of responses from the server
    //     std:: cout << "from " << inet_ntoa(sin.sin_addr) << " port " << ntohs(sin.sin_port) << " : " << buffer << std:: endl;
    //     recvmsg = buffer;
    // }
    memset(buffer, 0, sizeof(buffer));

    close(raw_david);


    return "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin.";

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

    std::cout << "checkksum ip: " << checksum << std::endl;

    long l = strtol(checksum.c_str(), nullptr, 16);

    return l;
}


std::string get_first_port(std::string message){
    std::string port;
    port = message.substr(58,4);
    return port;
}

std::string solve_oracle(std::string port1, std::string &port2,int port, char* ip){
    std::cout << "\nORACLE\n";
    int socket_fd;
    struct sockaddr_in address;
    //TODO:make the hardcoded string with the secret ports here insteead of gigaloop
    std:: string sentmsg = port1 + ",";
    char buffer[8192];
    std::string recvmsg;
    
    // Create a socket
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (socket_fd < 0)
    {
        perror("Error creating socket\n");
    }

    int low = 4000;
    int high = 4100;
    for(int i = low; i <= high; i++){
    
    // Set the address
    make_socket_address(&address, port, ip);

    //set timeout so recv doesnt halt forever on non responding ports
    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 50000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
    //send to each port a
    sentmsg = port1 + "," + std::to_string(i);
    sendto(socket_fd,sentmsg.c_str(),sizeof(sentmsg) - 1,0,(struct sockaddr *)&address,sizeof(address));
    

    socklen_t len = sizeof(address);
    int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

    if(nread > 0)
    {
        //get a list of responses from the server
        if (buffer[0] != 'I'){
            std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << " : " << buffer << std:: endl;
            recvmsg = buffer;
            break;
        }
    }
    memset(buffer, 0, sizeof(buffer));
    }
    

    close(socket_fd);

    if (recvmsg.substr(0,4) == port1){
       
        port2  = recvmsg.substr(4,8);
         std::cout << "port 2:  " << recvmsg.substr(4,8) << std::endl;
    }
    else{
        
        port2 = recvmsg.substr(0,4);
        std::cout << "port 2:  " << recvmsg.substr(0,4) << std::endl;
    }


    return recvmsg;
}

//NOTE: use the scanner to find the open ports and then use them as args for the puzzle solver

//Take a reference to a socket address and connect it to the given ip and port



std::vector<std::string> solve_puzzle(char *ip, int port1, int port2, int port3, int port4)
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
        read_timeout.tv_sec = 0;
        read_timeout.tv_usec = 50000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        //send to each port a
        sendto(socket_fd,sentmsg.c_str(),sizeof(sentmsg) - 1,0,(struct sockaddr *)&address,sizeof(address));
        

        socklen_t len = sizeof(address);
        int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len); 

        if(nread > 0)
        {
            //get a list of responses from the server
            std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << " : " << buffer << std:: endl;
            recvmsg = buffer;
            recv_vec.push_back(recvmsg);
        }
        memset(buffer, 0, sizeof(buffer));

    }
        close(socket_fd);


    return recv_vec;



}

std::string knock_knock(int secret_port1, int secret_port2,char* target_ip,std::string secret_message,std::vector<int> ports){
    //conducts the knocks in the order given by the oracle with the secret message as the payload
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

    //send to each port in the knock pattern
    for(int i = 0; i < ports.size(); i++){

        make_socket_address(&address, ports[i], target_ip);
        struct timeval read_timeout;
        read_timeout.tv_sec = 0;
        read_timeout.tv_usec = 50000;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
        std::cout << "sending to port " << ports[i] << ": " << secret_message << std::endl;
        sendto(socket_fd,secret_message.c_str(),sizeof(secret_message) - 1,0,(struct sockaddr *)&address,sizeof(address));

            //finally recieve the final messgage
        socklen_t len = sizeof(address);

        int nread = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr *)&address,&len);
        std::cout << "nread: " <<nread << std::endl; 

        if(nread > 0)
        {
            std:: cout << "from " << inet_ntoa(address.sin_addr) << " port " << ntohs(address.sin_port) << " : " << buffer << std:: endl;
            recvmsg = buffer;
        }
        memset(buffer, 0, sizeof(buffer));
    }    

    close(socket_fd);

    return recvmsg;

}


std::vector<int> parse_to_vector(std::string knock_pattern){
    //parses the knock pattern string to a vector of ints
    std::vector<int> vec;
    // std::stringstream ss(knock_pattern);
    std::string port;
    std::cout << knock_pattern << std::endl;

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



    std::cout << "Solving with ports " << port1 << ", " << port2 << ", " << port3 << ", " << port4 << " on " << target_IP << std::endl;

    //returns a vector of the messages from server
    std::vector<std::string> msg_list = solve_puzzle(target_IP, port1, port2, port3, port4);
    
    std::string spoof_ip;

    //checksum base 10
    long checksum;
    int open_ports[] = {port1, port2, port3, port4};
    std::string secret_port1;
    std::string secret_port2;
    std::string secret_phrase;
    std::string knock_pattern;

    for(int i = 0; i < msg_list.size(); i++){

        // checksum solver, check if message starts with h (Hello, group16!)
        
        if(msg_list[i][0] == 'H'){
            spoof_ip = get_spoof_ip(msg_list[i]);
            checksum = get_checksum(msg_list[i]);
            //TODO: solve checksum part
            std::cout << solve_checksum(open_ports[i],spoof_ip,checksum,target_IP) << std::endl;
        }
        if(msg_list[i][0] == 'M'){
            secret_port1 =  get_first_port(msg_list[i]);
            secret_port2 = "4001";
        }
        //solve oracle
        if(msg_list[i][0] == 'I'){
            //TODO: solve oracle port without hax 
            knock_pattern = solve_oracle(secret_port1,secret_port2,open_ports[i],target_IP);
        }
        
    }
    std::vector<int> knock_pattern_vector = parse_to_vector(knock_pattern);
    for(int i = 0; i < knock_pattern_vector.size(); i++){
        std::cout << "knock pattern vector: " << knock_pattern_vector[i] << std::endl;
    }

    secret_phrase = "Ennyn Durin Aran Moria. Pedo Mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion teithant i thiw hin.";
    std::cout << "secret phrase: " << secret_phrase << std::endl;


    // conduct the knocks.
    std::cout << secret_port1 << " " << secret_port2 << std::endl;
    int secret_port1_int = std::stoi(secret_port1,nullptr,10);
    int secret_port2_int = std::stoi(secret_port2,nullptr,10);
    // TODO: think it works, but perhaps the phrase is wrong
    std::string final_message = knock_knock(secret_port1_int,secret_port2_int
    ,target_IP,secret_phrase,knock_pattern_vector);


}   

// 4001 4008 4011 4090