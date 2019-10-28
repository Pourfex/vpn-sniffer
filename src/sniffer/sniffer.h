#ifndef SNIFFER_SNIFFER_H
#define SNIFFER_SNIFFER_H

#include <string>
#include <rxcpp/rx.hpp>
#include <tins/tins.h>
#include <memory>
#include "package.h"
#include <tins/tcp_ip/stream_follower.h>

namespace CapiTrain {

    class sniffer {

    public:
        explicit sniffer(const std::string& interfaceName);
        void start();
        [[nodiscard]] rxcpp::observable<package> getPackages() const;

    private:
        std::unique_ptr<Tins::Sniffer> tinsSniffer;
        void sniffCallback(Tins::TCPIP::Stream &stream);
        rxcpp::subjects::subject<package> packages;
    };

}


#endif //SNIFFER_SNIFFER_H
