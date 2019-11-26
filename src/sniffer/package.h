#ifndef SNIFFER_PACKAGE_H
#define SNIFFER_PACKAGE_H

#include <string>
#include <rxcpp/rx.hpp>

using std::string;
using rxcpp::observable;

namespace CapiTrain {

    enum package_type {
        TCP,
        UDP,
        UNKNOWN
    };

    struct package {
        unsigned long size;
        string ip;
        package_type type;
    };

}

#endif //SNIFFER_PACKAGE_H
