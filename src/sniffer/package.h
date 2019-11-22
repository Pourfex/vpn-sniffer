#ifndef SNIFFER_PACKAGE_H
#define SNIFFER_PACKAGE_H

#include <string>
#include <rxcpp/rx.hpp>

using std::string;
using rxcpp::observable;

namespace CapiTrain {

    struct package {
        unsigned long size;
        string ip;
        bool tcp;
    };

}

#endif //SNIFFER_PACKAGE_H
