#include "vpn-sniffer.h"
#include "package.h"

#include <iostream>
#include <utility>

using namespace CapiTrain;

using std::cout;
using std::endl;
using std::string;
using std::make_shared;
using std::move;
using std::chrono::seconds;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::pcap_error;

VPNSniffer::VPNSniffer(string interfaceName, string clientIP, string serverIP, string monitorIP)
        : clientIP(move(clientIP)),
          serverIP(move(serverIP)),
          monitorIP(move(monitorIP)),
          interfaceName(move(interfaceName)) {
}

void VPNSniffer::on_packet(PDU &pdu, bool isUdp) {
    auto ipPdu = pdu.rfind_pdu<Tins::IP>();

    auto dst = ipPdu.dst_addr().to_string();
    if (dst == this->serverIP || dst == this->clientIP || dst == this->monitorIP)
        return;

    auto size = pdu.size();
    package package;
    package.tcp = !isUdp;
    package.ip = dst;
    package.size = size;

    packets_subject.get_subscriber().on_next(package);
}

bool VPNSniffer::handle_pdu(PDU &pdu) {
    auto innerPdu = pdu.inner_pdu();
    if (innerPdu == nullptr) return false;

    auto that = innerPdu->inner_pdu();
    if (that == nullptr) return false;

    auto type = that->pdu_type();
    if (type == Tins::PDU::UDP || type == Tins::PDU::TCP) {
        auto isUDP = type == Tins::PDU::UDP;
        this->on_packet(pdu, isUDP);
        return true;
    }

    return false;
}

void VPNSniffer::start() {
    Sniffer sniffer(interfaceName);
    sniffer.sniff_loop([&](PDU &pdu) {
        handle_pdu(pdu);
        return true;
    });
}

observable<package> VPNSniffer::get_packets() const {
    return this->packets_subject.get_observable();
}

