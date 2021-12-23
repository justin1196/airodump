#include "airodump.h"
std::map <Mac, std::string> essid_map;
std::map <Mac, int> beacon_map;
void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

bool airodump(const u_char *packet){
    RadiotapHdr * radio = (struct RadiotapHdr*)packet;
    BeaconHdr * beacon = (struct BeaconHdr*)(packet + radio->len_);
    std::string ssid(beacon->ssid, beacon->len);
    if(beacon->frame_control != BEACON_TYPE) return false;
    if(beacon_map.find(beacon->bssid) == beacon_map.end()){
        beacon_map.insert({beacon->bssid,ONE});
        essid_map.insert({beacon->bssid,ssid});
    }
    else beacon_map[beacon->bssid] += ONE;
    for (auto itr = beacon_map.begin(); itr != beacon_map.end(); itr++){
        printf("bssid: %s  ", std::string(itr->first).data());
        printf("beacon: %d  ", itr->second);
        std::cout << "essid: " << essid_map[itr->first];
        printf("\n");
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if(!airodump(packet)) continue;
    }
    pcap_close(handle);
    
}