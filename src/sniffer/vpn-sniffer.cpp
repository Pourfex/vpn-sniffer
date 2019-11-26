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

void VPNSniffer::on_packet(PDU &pdu, package_type type) {
    auto ipPdu = pdu.rfind_pdu<Tins::IP>();

    auto dst = ipPdu.dst_addr().to_string();
    if (dst == this->clientIP || dst == this->monitorIP)
        return;

    auto src = ipPdu.src_addr().to_string();
    if (src == this->serverIP || src == this->clientIP || src == this->monitorIP)
        return;

    auto size = pdu.size();
    package package;
    package.type = type;
    package.ip = src;
    package.size = size;

    packets_subject.get_subscriber().on_next(package);
}

bool VPNSniffer::handle_pdu(PDU &pdu) {
    auto innerPdu = pdu.inner_pdu();
    if (innerPdu == nullptr) {
        this->on_packet(pdu, package_type::UNKNOWN);
        return false;
    }

    auto innerInnerPdu = innerPdu->inner_pdu();
    if (innerInnerPdu == nullptr) {
        this->on_packet(pdu, package_type::UNKNOWN);
        return false;
    }

    auto pduType = innerInnerPdu->pdu_type();
    auto packageType = package_type::UNKNOWN;
    if (pduType == Tins::PDU::UDP) {
        packageType = package_type::UDP;
    } else if (pduType == Tins::PDU::TCP) {
        packageType = package_type::TCP;
    }
    this->on_packet(pdu, packageType);
    return true;
}

void VPNSniffer::start() {
    SnifferConfiguration configuration;
    configuration.set_promisc_mode(true);
    configuration.set_immediate_mode(true);
    Sniffer sniffer(interfaceName, configuration);
    sniffer.sniff_loop([&](PDU &pdu) {
        handle_pdu(pdu);
        return true;
    });
}

observable<package> VPNSniffer::get_packets() const {
    return this->packets_subject.get_observable();
}

