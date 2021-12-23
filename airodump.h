#pragma once
#include <stdio.h>
#include <pcap.h>
#include "mac.h"
#include <string>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include <iostream>
#define BEACON_TYPE 0x80
#define ONE 1
#pragma pack(push, 1)
struct RadiotapHdr {
	uint8_t  ver_;
	uint8_t  pad_;
	uint16_t  len_;
	uint32_t  present_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BeaconHdr{
    uint16_t frame_control;
    uint16_t duration_id;
    Mac dest_addr;
    Mac src_addr;
    Mac bssid;
    uint16_t squence_num;
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;
    uint8_t tag_num;
    uint8_t len;
    char ssid[100];
};
#pragma pack(pop)
