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
        explicit VPNSniffer(string interfaceName, string clientIP, string serverIP);
        void start();
        [[nodiscard]] observable<stream_data> get_tcp_streams() const;
        [[nodiscard]] observable<udp_package> get_udp_packets() const;
    private:
        string clientIP;
        string serverIP;
        string interfaceName;

        subject<stream_data> streams;
        void on_new_stream(Stream& stream);
        void on_server_data(Stream& stream, const shared_ptr<subject<tcp_package>>& packages);

        subject<udp_package> udp_streams;
        bool handlePacket(Tins::PDU &some_pdu);

        void on_UDP_data(Tins::PDU &some_pdu);
    };

}


#endif //SNIFFER_VPN_SNIFFER_H
