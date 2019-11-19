#ifndef SNIFFER_SNIFFER_H
#define SNIFFER_SNIFFER_H

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

    class sniffer {

    public:
        explicit sniffer(string interfaceName, string clientIP, string serverIP);
        void start();
        [[nodiscard]] observable<stream_data> get_streams() const;
        [[nodiscard]] observable<stream_data> get_udp_streams() const;
    private:
        string clientIP;
        string serverIP;
        string interfaceName;

        subject<stream_data> streams;
        void on_new_stream(Stream& stream);
        void on_server_data(Stream& stream, const shared_ptr<subject<package>>& packages);

        subject<udp_package> udp_streams;
        void on_server_data(Tins::PDU& some_pdu, const shared_ptr<subject<udp_package>>& udp_packages);

        void on_UDP_data(Tins::PDU &some_pdu, const shared_ptr<subject<udp_package>> &udp_packages);
    };

}


#endif //SNIFFER_SNIFFER_H
