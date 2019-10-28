#ifndef SNIFFER_PACKAGE_H
#define SNIFFER_PACKAGE_H

#include <string>

namespace CapiTrain {

    struct package {
        std::string dest;
        int port;
        unsigned long size;
    };

}

#endif //SNIFFER_PACKAGE_H
