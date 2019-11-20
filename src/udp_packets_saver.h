#ifndef SNIFFER_UDP_PACKETS_SAVER_H
#define SNIFFER_UDP_PACKETS_SAVER_H

#include <iostream>
#include <chrono>
#include <string>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <fstream>
#include "sniffer/vpn-sniffer.h"

using std::cout;
using std::endl;

using std::chrono::seconds;

using std::vector;

using std::string;
using std::to_string;

using std::ostringstream;
using std::copy;
using std::ostream_iterator;

using std::fstream;

using CapiTrain::VPNSniffer;
using CapiTrain::udp_package;

void save_packets(const VPNSniffer &sniffer) {
    fstream udpPacketsFile;
    udpPacketsFile.open("udp_packets.txt");

    auto udpPackets$ = sniffer.get_udp_packets();
    udpPackets$
            .map([](const udp_package &packet) {
                return packet.ip + "," + to_string(packet.size);
            })
            .buffer_with_time(seconds(10))
            .filter([](const vector<string> &packets) {
                return !packets.empty();
            })
            .map([](const vector<string> &packets) {
                ostringstream stringStream;
                ostream_iterator<string> iterator(stringStream, "\n");
                copy(packets.begin(), packets.end() - 1, iterator);
                stringStream << packets.back();
                return stringStream.str();
            })
            .subscribe([&](const string& packets) {
                cout << "Writing " << packets;
                udpPacketsFile << packets;
            });
}

#endif //SNIFFER_UDP_PACKETS_SAVER_H
