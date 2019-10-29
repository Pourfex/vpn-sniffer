#include <rxcpp/rx.hpp>
#include "sniffer/sniffer.h"

using namespace CapiTrain;

void sleepForever() {
    std::promise<void>().get_future().wait();
}

int main() {
    CapiTrain::sniffer sniffer("wlp8s0");
    std::thread thread([&]() {
        sniffer.start();
    });

    auto packages = sniffer.get_packages();
    packages.subscribe([](const package& p) {
        //std::cout << p.dest << ":" << p.port << " -> " << p.size << std::endl;
    });

    sleepForever();
}
