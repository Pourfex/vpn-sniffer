#ifndef SNIFFER_VPN_SNIFFER_H
#define SNIFFER_VPN_SNIFFER_H

#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>
#include <rxcpp/rx.hpp>

#include <string>
#include <memory>
#include <map>

#include "package.h"

using Tins::TCPIP::Stream;
using rxcpp::observable;
using rxcpp::subjects::subject;

using std::shared_ptr;
using std::string;

namespace CapiTrain {

    class VPNSniffer {

    public:
        explicit VPNSniffer(string interfaceName, string clientIP, string serverIP, string monitorIP);
        void start();
        [[nodiscard]] observable<package> get_packets() const;
    private:
        string clientIP;
        string serverIP;
        string monitorIP;
        string interfaceName;

        subject<package> packets_subject;
        bool handle_pdu(Tins::PDU &pdu);

        void on_packet(Tins::PDU &pdu, bool isUdp);
    };

}

#endif //SNIFFER_VPN_SNIFFER_H
