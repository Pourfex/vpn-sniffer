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
        [[nodiscard]] rxcpp::observable<package> get_packages() const;

    private:
        std::unique_ptr<Tins::Sniffer> tinsSniffer;
        rxcpp::subjects::subject<package> packages;
        void on_new_stream(Stream &stream);
        void on_server_data(Stream &stream);
    };

}


#endif //SNIFFER_SNIFFER_H
