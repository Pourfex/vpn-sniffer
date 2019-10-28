#ifndef SNIFFER_PACKAGE_H
#define SNIFFER_PACKAGE_H

#include <string>

namespace CapiTrain {

    struct package {
        std::string src;
        std::string dest;
        uint32_t size;
    };

}

#endif //SNIFFER_PACKAGE_H
