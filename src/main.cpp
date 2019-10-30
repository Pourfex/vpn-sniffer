#include <rxcpp/rx.hpp>
#include <thread>
#include <cxxopts.hpp>
#include "sniffer/sniffer.h"

using rxcpp::observable;
using rxcpp::make_subscriber;

using std::cout;
using std::endl;
using std::thread;
using std::string;

using cxxopts::Options;

using namespace CapiTrain;

void sleep_forever() {
    std::promise<void>().get_future().wait();
}

void on_new_stream(const stream_data &stream_data) {
    auto packages$ = stream_data.packages$;
    cout << "New stream with ip: " << stream_data.ip << endl;
    packages$
            .reduce(
                    0,
                    [](int totalSize, const package &p) {
                        return totalSize + p.size;
                    }
            )
            .subscribe([&, stream_data](int totalSize) {
                cout << "Stream " << stream_data.ip << " finished with: " << totalSize << endl;
            });
}

Options createOptions() {
    Options options("CapiTrain VPN Sniffer");
    options.add_options()
            ("interface-name", "Name of the interface", cxxopts::value<string>()->default_value("en0"))
            ("client-ip", "IP of the client (your IP)", cxxopts::value<string>()->default_value(""))
            ("server-ip", "IP of the server (the VPN server's IP)", cxxopts::value<string>()->default_value(""));
    return options;
}

int main(int argc, char *argv[]) {
    auto options = createOptions();
    auto parsedOptions = options.parse(argc, argv);

    auto interfaceName = parsedOptions["interface-name"].as<string>();
    auto clientIP = parsedOptions["client-ip"].as<string>();
    auto serverIP = parsedOptions["server-ip"].as<string>();
    CapiTrain::sniffer sniffer(interfaceName, clientIP, serverIP);
    thread thread([&]() {
        cout << "Starting sniffer on interface " << interfaceName << endl;
        sniffer.start();
        cout << "Sniffer started !" << endl;
    });

    auto streams$ = sniffer.get_streams();
    streams$.subscribe(&on_new_stream);

    sleep_forever();
}
