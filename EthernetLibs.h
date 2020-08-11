#include<iostream>
#include<crafter.h>
#include<string>
#include <algorithm>
#include <vector>
#include <bits/stdc++.h>
#define iface "ens33"
using namespace std;
using namespace Crafter;


int NextSeqNumber(TCP* tcp_layer){
    long seq_num = tcp_layer->GetSeqNumber();
    int len = tcp_layer->GetPayloadSize();
    return seq_num+len;
}
/*take to pointer of to packets and compere the ip and the mac adresses to check if there is connection betwen them*/
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
        if (seq_number_packet1 == ack_number_packet2){
            cout<< "packet1 --> packet2";
            return true;
        } 
        if( seq_number_packet2 == ack_number_packet1){
            cout << "packet2 --> packet1";
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
        
        if (is_ip_in(going_inside_packets, ip, "in") != 9999 ){
            if (verfiySYN_ACK(packet,going_inside_packets[is_ip_in(going_inside_packets, ip, "inside")])){
                /*found that there is connection between the packets*/
                /*now i need to hundle that*/
            }
        }
        else{
            /*didntfound, lets add it*/
        }

        /*hundle come out packet*/
    }
    if (type == "out"){
        /*hundle come out packet*/
    }
    else{
        /*hundle eror<- drop packet*/
    }
    
}
void packetconnecsion(Packet* packet){

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