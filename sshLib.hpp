#ifndef sshLib_h
#define sshLib_h
#include <iostream>
#include <stdlib.h>
#include <crafter.h>
#include "EthernetLibs.hpp"
#include "httpLib.hpp"
int ssh_run=-1;

/*payload.substr(0,3).compare("GET")==0)*/
bool check_shh(Packet* packet){
    RawLayer* raw_layer = packet->GetLayer<RawLayer>();
    string payload = raw_layer->GetStringPayload();
    if(payload.substr(0,3).compare("SSH")==0){
        return true;
    }
    return false;
}
void ssh_hundle(Packet* packet, void* user){
    
    if (!disconnect(packet)){
        /*hundle the tcp: ttl and save data + begin of the raw_payload*/
        

    }else{
        ssh_run = 0;

    }
}

void ssh_hundle_for_new_packet(Packet* packet1, Packet* packet2){
    if ((check_shh(packet1) || check_shh(packet2)) &&verfiySYN_ACK(packet1, packet2)){
        IP* ip_layer_packet1 = packet1->GetLayer<IP>();
        IP* ip_layer_packet2 = packet2->GetLayer<IP>();
       /*needs to stop when get FIN flag, until then--> looking for other packet in the seesion(keep the seesion by syn, ack and ports)*/
        string credentials = "((dst" + ip_layer_packet1->GetDestinationIP() + "or dst " + ip_layer_packet2->GetDestinationIP() +") and ( src " + ip_layer_packet1->GetSourceIP()+ " or src "+ ip_layer_packet2->GetSourceIP() + "))";  
        Sniffer ssh_sniffer_packet1(credentials,iface,ssh_hundle);
        ssh_sniffer_packet1.Capture(ssh_run);


    }
}






















#endif
