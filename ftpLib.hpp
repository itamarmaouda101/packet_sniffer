#ifndef ftpLib_h
#define ftpLib_h
#include"EthernetLibs.hpp"
#include <crafter.h>
#include <iostream>
#include "sshLib.hpp"
#include "httpLib.hpp"
#include <string>
using namespace std;
int ftp_on = -1;
bool ftp_check(Packet* packet){
    RawLayer* raw_layer = packet->GetLayer<RawLayer>();
    string payload = raw_layer->GetStringPayload();
    size_t finder =payload.find("FTP"); 
    if (finder != 0 && !disconnect(packet)){
        return true;
    }
    return false;
}
void hundle_ftp(Packet* packet, void* user){
    /*hundle the ftp packet-> save data?*/

}
void ftp_conn(Packet* packet1, Packet* packet2){
    if (ftp_check(packet1) || ftp_check(packet2)){
        /*hundle ftp*/
        IP* ip_layer_packet1 = packet1->GetLayer<IP>();
        IP* ip_layer_packet2 = packet2->GetLayer<IP>();
       /*needs to stop when get FIN flag, until then--> looking for other packet in the seesion(keep the seesion by syn, ack and ports)*/
        string credentials = "((dst" + ip_layer_packet1->GetDestinationIP() + "or dst " + ip_layer_packet2->GetDestinationIP() +") and ( src " + ip_layer_packet1->GetSourceIP()+ " or src "+ ip_layer_packet2->GetSourceIP() + "))";  

        Sniffer ftp_sniffer(credentials,iface, hundle_ftp);
        ftp_sniffer.Capture(ftp_on);
        
    }
}










#endif