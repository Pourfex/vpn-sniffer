#include <iostream>
#include <vector>
#include <chrono>
#include <rxcpp/rx.hpp>
#include "sniffer/sniffer.h"


void sleepForever() {
    std::promise<void>().get_future().wait();
}

int main() {
    CapiTrain::sniffer sniffer("ens3");
    std::thread thread([&]() {
        sniffer.start();
    });

    auto bufferTime = std::chrono::milliseconds(1000);
    sniffer.getPackages().buffer_with_time(bufferTime).subscribe(
            [](const std::vector<struct CapiTrain::package> &packages) {
                //std::cout << packages.size() << std::endl;
            }
    );

    sleepForever();
}