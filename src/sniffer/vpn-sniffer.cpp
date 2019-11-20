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

VPNSniffer::VPNSniffer(string interfaceName, string clientIP, string serverIP)
        : clientIP(move(clientIP)),
          serverIP(move(serverIP)),
          interfaceName(move(interfaceName)) {
}

void VPNSniffer::on_UDP_data(PDU &some_pdu) {
    auto ip = some_pdu.rfind_pdu<Tins::IP>();
    if (ip.dst_addr().to_string() == this->clientIP) {
        return;
    }
    auto size = some_pdu.size();
    udp_package udp_package;
    udp_package.ip = ip.dst_addr().to_string();
    udp_package.size = size;

    udp_streams.get_subscriber().on_next(udp_package);
}

bool VPNSniffer::handlePacket(PDU &some_pdu) {
    auto ip = some_pdu.rfind_pdu<Tins::IP>();

    auto it = some_pdu.inner_pdu();
    if (it == nullptr) return false;

    auto that = it->inner_pdu();
    if (that == nullptr) return false;

    auto type = that->pdu_type();
    if (type == Tins::PDU::UDP) {
        this->on_UDP_data(some_pdu);
        return true;
    }

    return false;
}

void VPNSniffer::start() {
    StreamFollower streamFollower;
    streamFollower.new_stream_callback([&](Stream &stream) {
        this->on_new_stream(stream);
    });

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(interfaceName, config);
    sniffer.sniff_loop([&](PDU &pdu) {
        if (!handlePacket(pdu)) {
            //streamFollower.process_packet(pdu); c'est cassé :(
        }
        return true;
    });
}

observable<stream_data> VPNSniffer::get_tcp_streams() const {
    return this->streams.get_observable();
}

observable<udp_package> VPNSniffer::get_udp_packets() const {
    return this->udp_streams.get_observable();
}

void VPNSniffer::on_new_stream(Stream &stream) {
    auto serverIp = stream.server_addr_v4().to_string();

    if (serverIp == this->serverIP) {
        return;
    }

    auto packages = make_shared<subject<tcp_package>>();
    auto packages$ = packages->get_observable();
    stream_data streamData{
            .ip = serverIp,
            .packages$ = packages$
    };
    this->streams.get_subscriber().on_next(streamData);

    stream.server_data_callback([&, packages](Stream &stream) {
        this->on_server_data(stream, packages);
    });

    stream.stream_closed_callback([&, packages](Stream &stream) {
        packages->get_subscriber().on_completed();
    });
}

void VPNSniffer::on_server_data(Stream &stream, const shared_ptr<subject<tcp_package>> &packages) {
    if (stream.client_addr_v4().to_string() == this->clientIP) {
        return;
    }
    auto size = stream.server_payload().size();
    tcp_package package{
            .size = size
    };
    packages->get_subscriber().on_next(package);
}


