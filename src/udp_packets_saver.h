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
using std::chrono::milliseconds;
using std::chrono::duration_cast;
using std::chrono::system_clock;

using std::vector;

using std::string;
using std::to_string;

using std::ostringstream;
using std::copy;
using std::ostream_iterator;

using std::fstream;

using CapiTrain::VPNSniffer;
using CapiTrain::package;
using CapiTrain::package_type;

const auto BUFFER_TIME = seconds(10);

string get_timestamp() {
    auto ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
    );
    return to_string(ms.count());
}

void save_packets(const VPNSniffer &sniffer) {
    auto udpPackets$ = sniffer.get_packets();
    udpPackets$
            .map([](const package &packet) {
                string type = "unknown";
                if (packet.type == package_type::UDP) {
                    type = "udp";
                } else if (packet.type == package_type::TCP) {
                    type = "tcp";
                }
                return type + "," + packet.ip + "," + to_string(packet.size) + "," + get_timestamp();
            })
            .buffer_with_time(BUFFER_TIME)
            .filter([](const vector<string> &packets) {
                return !packets.empty();
            })
            .tap([](const vector<string> &packets) {
                cout << "Writing " << packets.size() << " packets " << endl;
            })
            .map([](const vector<string> &packets) {
                ostringstream stringStream;
                ostream_iterator<string> iterator(stringStream, "\n");
                copy(packets.begin(), packets.end() - 1, iterator);
                stringStream << packets.back() << "\n";
                return stringStream.str();
            })
            .subscribe([&](const string &packets) {
                fstream udpPacketsFile;
                udpPacketsFile.open("packets.txt", fstream::out | fstream::app);
                udpPacketsFile << packets;
            });
}

#endif //SNIFFER_UDP_PACKETS_SAVER_H
