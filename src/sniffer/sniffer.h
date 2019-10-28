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

namespace CapiTrain {

    class sniffer {

    public:
        explicit sniffer(const std::string& interfaceName);
        void start();
        [[nodiscard]] rxcpp::observable<package> getPackages() const;

    private:
        std::unique_ptr<Tins::Sniffer> tinsSniffer;

        std::map<long, int> active_packets;
        rxcpp::subjects::subject<package> packages;

        long streamId;
        long get_next_stream_id();

        void on_new_stream(Stream &stream);
        void on_client_data(Stream &stream, long currentStreamId);
        void on_server_data(Stream &stream, long currentStreamId);
        void on_connection_closed(Stream &stream, long currentStreamId);
    };

}


#endif //SNIFFER_SNIFFER_H
