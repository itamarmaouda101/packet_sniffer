#include<iostream>
#include<crafter.h>
using namespace std;
using namespace Crafter;
int NextSeqNumber(TCP* tcp_layer){
    long seq_num = tcp_layer->GetSeqNumber();
    int len = tcp_layer->GetPayloadSize();
    return seq_num+len;
}