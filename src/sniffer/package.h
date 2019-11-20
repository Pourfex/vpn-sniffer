#ifndef SNIFFER_PACKAGE_H
#define SNIFFER_PACKAGE_H

#include <string>
#include <rxcpp/rx.hpp>

using std::string;
using rxcpp::observable;

namespace CapiTrain {

    struct tcp_package {
        unsigned long size;
    };

    struct udp_package {
        unsigned long size;
        string ip;
    };

    struct stream_data {
        string ip;
        observable<tcp_package> packages$;
    };

}

#endif //SNIFFER_PACKAGE_H
