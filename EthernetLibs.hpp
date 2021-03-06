#ifndef EthernetLibs
#define EthernetLibs
#include<iostream>
#include<crafter.h>
#include<string>
#include <algorithm>
#include <vector>
#include "httpLib.hpp"
#include <bits/stdc++.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include <netdb.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#define iface "ens33"
using namespace std;
using namespace Crafter;






/*program that findes host name*/
/*----START_CODING---*/
void check_host_name(int hostname){
    /*returns the hostname of the local computer*/
    if (hostname == -1){
        perror("gethostname");
        exit(1);
    }
}
void check_host_entry(struct hostent * hostentry){
    /*find host info from host name*/
    if (hostentry == NULL){
        perror("gethostname");
        exit(1);   
    }
}
void IP_formatter(char *IPbuffer){
    /*corvent ip string to dotted decimal format*/
    if (NULL ==IPbuffer){
        perror("inet_ntoa");
        exit(1);
    }
}
void get_hostname(int hostname){
    char host[256];
    char *IP;
    struct hostent *host_entry;
    /*   hostname = gethostname(host, sizeof(host)); //find the host name*/
    check_host_name(hostname);
    host_entry = gethostbyname(host);
    check_host_entry(host_entry);
   IP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])); //Convert into IP string    cout<< "Current host name: " << host <<endl;
    cout<< "host ip: "<< IP<<endl; 
}


/*---END_OF_CODING*/


int NextSeqNumber(TCP* tcp_layer){
    /*the next seq number is other packet ack*/
    long seq_num = tcp_layer->GetSeqNumber();
    int len = tcp_layer->GetPayloadSize();
    return seq_num+len;
}
/*take to pointer of to packets and compere the ip and the mac adresses to check if there is connection betwen them*/
bool check_ports(Packet* packet1, Packet* packet2){
    IP* ip_layer_packet1 = packet1->GetLayer<IP>();
    IP* ip_layer_packet2 = packet2->GetLayer<IP>();
    TCP* tcp_layer_packet1 = packet1->GetLayer<TCP>();
    TCP* tcp_layer_packet2 = packet2->GetLayer<TCP>();
    UDP* udp_layer_packet1 = packet1->GetLayer<UDP>();
    UDP* udp_layer_packet2 = packet2->GetLayer<UDP>();
    string packet1_src_port = ip_layer_packet1->GetSourceIP();
    string packet2_src_port = ip_layer_packet2->GetSourceIP();
    string packet1_dst_port;
    string packet2_dst_port;
    if (tcp_layer_packet1 && tcp_layer_packet2){
        packet1_dst_port = tcp_layer_packet1->GetDstPort();
        packet2_dst_port = tcp_layer_packet2->GetDstPort(); 
        if ( packet1_src_port == packet2_dst_port && packet2_src_port == packet1_dst_port){
            return true;
        }
    }
    else if (udp_layer_packet1 && udp_layer_packet2){
        packet1_dst_port = udp_layer_packet1->GetDstPort();
        packet2_dst_port = udp_layer_packet2->GetDstPort();
        if (packet1_src_port == packet2_dst_port && packet2_src_port == packet1_dst_port){
            return true;
        }
    
    }
        return false;
     
}
bool sameaddr(Packet* packet1, Packet* packet2){
    bool ip_verfiy= false;
    bool mac_verfiy = false;
    IP* ip_layer_packet1 = packet1->GetLayer<IP>();
    IP* ip_layer_packet2 = packet2->GetLayer<IP>();
    Ethernet* Ether_layer_packet1 = packet1->GetLayer<Ethernet>();
    Ethernet* Ether_layer_packet2 = packet2->GetLayer<Ethernet>();
    string IP_dst_packet1= ip_layer_packet1->GetDestinationIP();
    string IP_dst_packet2 = ip_layer_packet2->GetDestinationIP();
    string Destination_ip_packet1 = ip_layer_packet1->GetSourceIP();
    string Destination_ip_packet2 = ip_layer_packet2->GetSourceIP();
    string MAC_src_packet1 = Ether_layer_packet1->GetSourceMAC();
    string MAC_src_packet2 = Ether_layer_packet2->GetSourceMAC();
    string MAC_dst_packet1 = Ether_layer_packet1->GetDestinationMAC();
    string MAC_dst_packet2 = Ether_layer_packet2->GetDestinationMAC();
    if(IP_dst_packet1 == Destination_ip_packet2 && IP_dst_packet2 == Destination_ip_packet1){
        ip_verfiy = true;
    }
    if (MAC_src_packet1 == MAC_dst_packet2 && MAC_src_packet2 == MAC_dst_packet1){
        mac_verfiy = true;
    }
    if (mac_verfiy && ip_verfiy){
        return true;
    }
    return false;


}


bool verfiySYN_ACK(Packet* packet1, Packet* packet2){
    if (sameaddr(packet1, packet2)){
        TCP* tcp_layer_packet1 = packet1->GetLayer<TCP>();
        TCP* tcp_layer_packet2 = packet2->GetLayer<TCP>();
        int seq_number_packet1 = tcp_layer_packet1->GetSeqNumber();
        int seq_number_packet2 = tcp_layer_packet2->GetSeqNumber();
        int ack_number_packet1 = tcp_layer_packet1->GetAckNumber();
        int ack_number_packet2 = tcp_layer_packet2->GetAckNumber();
        if (seq_number_packet2 == ack_number_packet1){
            cout<< "packet2 --> packet1";
            return true;
        } 
        if( seq_number_packet1 == ack_number_packet2){
            cout << "packet1 --> packet2";
            return true;
        }
        else{
        cout<< "there's not connection";
        return false;
        }
    }
    return false;
    

}
string check_in_out(Packet* packet){
    IP* ip_layer = packet->GetLayer<IP>();
    string my_ip = GetMyIP(iface);

    if (ip_layer->GetDestinationIP() == my_ip){
        /*GOING INSIDE*/
        return "in";
    }
    if(ip_layer->GetSourceIP() == my_ip){
        /*GOING OUTSIDE*/
        return "out";
    }
    else{
        /*ERROR*/
        return "error";
    }
}

std::vector <Packet*> going_outside_packets;
std::vector <Packet*> going_inside_packets;


int is_ip_in(vector <Packet*> packets, string ip, string type){
    if (type == "inside"){
        for(int i=0; packets.size();i++){
            Packet* packet = packets[i];
            IP* ip_layer = packet->GetLayer<IP>();
            string arr_dst_ip = ip_layer->GetDestinationIP(); 
            if (arr_dst_ip==ip){
                return i;
            }
        }
    }
    if (type == "outside"){
         for(int i=0; packets.size();i++){
            IP* ip_layer = packets[i]->GetLayer<IP>();
            string arr_src_ip = ip_layer->GetSourceIP(); 
            if (arr_src_ip==ip){
                return i;
            }
        }

    }
    return 9999;

}
void new_packet(Packet* packet){
    string type = check_in_out(packet);
    IP* ip_layer = packet->GetLayer<IP>();
    string ip = ip_layer->GetSourceIP();
    if (type == "in"){
        
        if (is_ip_in(going_inside_packets, ip, "inside") != 9999 ){
            if (verfiySYN_ACK(packet,going_outside_packets[is_ip_in(going_outside_packets, ip, "outside")])){
                /*found that there is connection between the packets*/
                /*now i need to hundle that*/
            }
        }
        else{
            going_inside_packets.push_back(packet);
            new_packet(packet);
            /*didntfound, lets add it*/
        }

        /*hundle come out packet*/
    }
    if (type == "out"){
        if (is_ip_in(going_inside_packets, ip, "outside") != 9999 ){
            if (verfiySYN_ACK(packet,going_inside_packets[is_ip_in(going_inside_packets, ip, "inside")])){
                /*found that there is connection between the packets*/
                /*now i need to hundle that*/
            }
        }
        else{
            going_inside_packets.push_back(packet);
            new_packet(packet);
        }
        /*hundle come out packet*/
    }
    else{
        /*hundle eror<- drop packet*/
    }
    
}
void FromByte(unsigned char c, bool b[8])
{
    for (int i=0; i < 8; ++i)
        b[i] = (c & (1<<i)) != 0;
}

bool disconnect(Packet* packet1){
    
    TCP* tcp_layer_packet1 = packet1->GetLayer<TCP>();
    //TCP* tcp_layer_packet2 = packet2->GetLayer<TCP>();
    if (tcp_layer_packet1){
        if (tcp_layer_packet1->GetFIN()){/**/
            return true;
        }
        else {
            return false;
        }
    }
    return false;

}
void tcp_flags(Packet* sniff_packet){
	TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
	cout<<"tcp ack number: "<< tcp_layer->GetAckNumber()<<endl;
	cout<<"packet flags: "<< tcp_layer->GetFlags()<< endl;
	cout<< "tcp FIN Flag:"<< tcp_layer->GetFIN()<<endl;
	cout<<"tcp CWR Flag:"<< tcp_layer->GetCWR()<< endl;
	cout << "tcp ECE Flag:"<< tcp_layer->GetECE() << endl;
	cout << "tcp PSH Flag:"<< tcp_layer->GetPSH()<< endl;
	cout << "tcp RST Flag:"<< tcp_layer->GetRST() << endl;
	cout<< "tcp SYN Flag:"<< tcp_layer->GetSYN() << endl;
	cout << "tcp URG Flag:"<< tcp_layer->GetURG() <<endl;
}

/*packet_expulison doset work yet 
**after programing the layer 5 protocols idenefision ill handule that*/

	

/*void packet_expulsion(Packet* sniff_packet, void* user){
	size_t NumberOfLayers = sniff_packet->GetLayerCount();
	TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
	UDP* udp_layer = sniff_packet->GetLayer<UDP>();
	RawLayer* raw_layer = sniff_packet->GetLayer<RawLayer>();
	byte* raw_ptr;

	if (tcp_layer){
		Layer* top_layer = tcp_layer->GetTopLayer();
		Payload payload = top_layer->GetPayload();
		size_t data = top_layer->GetData(raw_ptr);
		cout <<data<<endl;
	}
	if (udp_layer){
		Layer* top_layer = udp_layer->GetTopLayer();
		Payload payload = top_layer->GetPayload();
		size_t data = top_layer->GetData(raw_ptr);
		cout <<data<<endl;
	}
	Layer* top_layer = raw_layer->GetTopLayer(); 

	byte*  payload_bytes;

	Payload payload = top_layer->GetPayload();
	size_t data = top_layer->GetRawData(raw_ptr);
	cout <<data<<endl;
	/*
	size_t payload_size_t = top_layer->GetPayload(payload_bytes);
	cout<< "payload:\n\n"<< endl;
	cout<<payload.GetString()<<endl;
	cout<<"\n\n payload (bytes)\n\n"<<endl;
	cout<<payload_bytes.G<<endl;
	cout<<"\n"<< payload_size_t<<endl;
	*/



	
	






	

	
#endif