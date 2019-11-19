#include "sniffer.h"
#include "package.h"

#include <iostream>
#include <chrono>
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

sniffer::sniffer(string interfaceName, string clientIP, string serverIP)
        : clientIP(move(clientIP)),
          serverIP(move(serverIP)),
          interfaceName(move(interfaceName)) {
}

std::string PDUTypeLookup(PDU::PDUType type){
    switch (type)
    {
        default:      return "[Unknown OS_type]";
        case PDU::RAW: return "RAW";
            break;
        case PDU::ETHERNET_II: return "ETHERNET_II";
            break;
        case PDU::IEEE802_3: return "IEEE802_3";
            break;
        case PDU::RADIOTAP: return "RADIOTAP";
            break;
        case PDU::DOT11: return "DOT11";
            break;
        case PDU::DOT11_ACK: return "DOT11_ACK";
            break;
        case PDU::DOT11_ASSOC_REQ: return "DOT11_ASSOC_REQ";
            break;
        case PDU::DOT11_ASSOC_RESP: return "DOT11_ASSOC_RESP";
            break;
        case PDU::DOT11_AUTH: return "DOT11_AUTH";
            break;
        case PDU::DOT11_BEACON: return "DOT11_BEACON";
            break;
        case PDU::DOT11_BLOCK_ACK: return "DOT11_BLOCK_ACK";
            break;
        case PDU::DOT11_BLOCK_ACK_REQ: return "DOT11_BLOCK_ACK_REQ";
            break;
        case PDU::DOT11_CF_END: return "DOT11_CF_END";
            break;
        case PDU::DOT11_DATA: return "DOT11_DATA";
            break;
        case PDU::DOT11_CONTROL: return "DOT11_CONTROL";
            break;
        case PDU::DOT11_DEAUTH: return "DOT11_DEAUTH";
            break;
        case PDU::DOT11_DIASSOC: return "DOT11_DIASSOC";
            break;
        case PDU::DOT11_END_CF_ACK: return "DOT11_END_CF_ACK";
            break;
        case PDU::DOT11_MANAGEMENT: return "DOT11_MANAGEMENT";
            break;
        case PDU::DOT11_PROBE_REQ: return "DOT11_PROBE_REQ";
            break;
        case PDU::DOT11_PROBE_RESP: return "DOT11_PROBE_RESP";
            break;
        case PDU::DOT11_PS_POLL: return "DOT11_PS_POLL";
            break;
        case PDU::DOT11_REASSOC_REQ: return "DOT11_REASSOC_REQ";
            break;
        case PDU::DOT11_REASSOC_RESP: return "DOT11_REASSOC_RESP";
            break;
        case PDU::DOT11_RTS: return "DOT11_RTS";
            break;
        case PDU::DOT11_QOS_DATA: return "DOT11_QOS_DATA";
            break;
        case PDU::LLC: return "LLC";
            break;
        case PDU::SNAP: return "SNAP";
            break;
        case PDU::IP: return "IP";
            break;
        case PDU::ARP: return "ARP";
            break;
        case PDU::TCP: return "TCP";
            break;
        case PDU::UDP: return "UDP";
            break;
        case PDU::ICMP: return "ICMP";
            break;
        case PDU::BOOTP: return "BOOTP";
            break;
        case PDU::DHCP: return "DHCP";
            break;
        case PDU::EAPOL: return "EAPOL";
            break;
        case PDU::RC4EAPOL: return "RC4EAPOL";
            break;
        case PDU::RSNEAPOL: return "RSNEAPOL";
            break;
        case PDU::DNS: return "DNS";
            break;
        case PDU::LOOPBACK: return "LOOPBACK";
            break;
        case PDU::IPv6: return "IPv6";
            break;
        case PDU::ICMPv6: return "ICMPv6";
            break;
        case PDU::SLL: return "SLL";
            break;
        case PDU::DHCPv6: return "DHCPv6";
            break;
        case PDU::DOT1Q: return "DOT1Q";
            break;
        case PDU::PPPOE: return "PPPOE";
            break;
        case PDU::STP: return "STP";
            break;
        case PDU::PPI: return "PPI";
            break;
        case PDU::IPSEC_AH: return "IPSEC_AH";
            break;
        case PDU::IPSEC_ESP: return "IPSEC_ESP";
            break;
        case PDU::PKTAP: return "PKTAP";
            break;
        case PDU::MPLS: return "MPLS";
            break;
        case PDU::UNKNOWN: return "UNKNOWN";
            break;
        case PDU::USER_DEFINED_PDU: return "USER_DEFINED_PDU";
            break;
    }
}

void sniffer::on_UDP_data(PDU &some_pdu) {
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

bool sniffer::handlePacket(PDU &some_pdu) {;
    const Tins::IP &ip = some_pdu.rfind_pdu<Tins::IP>(); // non-const works as well
    //std::cout << "Destination address: " << ip.dst_addr() << std::endl;

    PDU::PDUType type = some_pdu.pdu_type();
    //std::cout << "1- type : " << PDUTypeLookup(type) << std::endl;

    auto it = some_pdu.inner_pdu();
    if(it != NULL){
        type = it->pdu_type();
        //std::cout << "2- type : " << PDUTypeLookup(type) << std::endl;

        auto that = it->inner_pdu();
        if(that != NULL){

            type = that->pdu_type();
            //std::cout << PDUTypeLookup(type)  << "," << some_pdu.size() << std::endl;
            if(type == Tins::PDU::UDP){
                //std::cout << "UDP packet received" << std::endl;
                const Tins::IP &ip = some_pdu.rfind_pdu<Tins::IP>(); // non-const works as well
                //std::cout << "Destination address: " << ip.dst_addr() << std::endl;
                this->on_UDP_data(some_pdu);
                return true;
            }else{
                std::cout << "Another type packet received" << std::endl;
            }
        }
    }
    return false;
}

void sniffer::start() {
    StreamFollower streamFollower;
    streamFollower.new_stream_callback([&](Stream &stream) {
        this->on_new_stream(stream);
    });

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    //config.set_filter("udp"); //"tcp" or none if we want to display all !
    Sniffer sniffer(interfaceName, config);
    sniffer.sniff_loop([&](PDU &pdu) {
        if(!handlePacket(pdu)){
            //streamFollower.process_packet(pdu); c'est cassé :(
        }
        return true;
    });



    /*Sniffer sniffer("wlp8s0");

    sniffer.sniff_loop(handlePacket);*/
}



observable<stream_data> sniffer::get_streams() const {
    return this->streams.get_observable();
}

observable<udp_package> sniffer::get_udp_streams() const {
    return this->udp_streams.get_observable();
}

void sniffer::on_new_stream(Stream &stream) {
    auto serverIp = stream.server_addr_v4().to_string();

    if (serverIp == this->serverIP) {
        return;
    }

    auto packages = make_shared<subject<package>>();
    auto packages$ = packages->get_observable();
    stream_data streamData{
            .ip = serverIp,
            .packages$ = packages$
    };
    this->streams.get_subscriber().on_next(streamData);

    auto debounceTime = seconds(120);

    packages$
            .skip(1)
            .debounce(debounceTime)
            .subscribe([&, packages](const package &p) {
                packages->get_subscriber().on_completed();
            });

    stream.server_data_callback([&, packages](Stream &stream) {
        this->on_server_data(stream, packages);
    });

    stream.stream_closed_callback([&, packages](Stream &stream) {
        packages->get_subscriber().on_completed();
    });
}

void sniffer::on_server_data(Stream &stream, const shared_ptr<subject<package>> &packages) {
    if (stream.client_addr_v4().to_string() == this->clientIP) {
        return;
    }
    auto size = stream.server_payload().size();
    package package{
            .size = size
    };
    packages->get_subscriber().on_next(package);
}


