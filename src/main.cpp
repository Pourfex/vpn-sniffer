#include <vector>
#include <chrono>
#include <rxcpp/rx.hpp>
#include "sniffer/sniffer.h"

using namespace CapiTrain;

void sleepForever() {
    std::promise<void>().get_future().wait();
}

int main() {
    CapiTrain::sniffer sniffer("ens3");
    std::thread thread([&]() {
        sniffer.start();
    });

    auto packages = sniffer.get_packages();
    auto groupedIps = packages
            .tap([&](const package &p) {
                std::cout << p.dest << ":" << p.size << std::endl;
            })
            .group_by(
                    [&](const package &p) { return p.dest; },
                    [&](const package &p) { return p; }
            )
            .map([&](const rxcpp::observable<package> &packages) {
                return packages
                    .buffer_with_time(std::chrono::milliseconds(1000))
                    .tap([&](const std::vector<package> &packages) {
                        std::cout << packages.size() << std::endl;
                    });
            })
            .merge();

    groupedIps.subscribe();

    sleepForever();
}