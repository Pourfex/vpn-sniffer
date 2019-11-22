#include <rxcpp/rx.hpp>
#include <cxxopts.hpp>
#include <thread>
#include <tins/tins.h>

#include "sniffer/vpn-sniffer.h"
#include "udp_packets_saver.h"

using rxcpp::observable;
using rxcpp::make_subscriber;

using std::cout;
using std::cerr;
using std::endl;

using std::thread;
using std::string;
using std::chrono::seconds;
using std::vector;
using std::transform;
using std::find;

using cxxopts::Options;

using namespace CapiTrain;

void sleep_forever() {
    std::promise<void>().get_future().wait();
}

Options createOptions() {
    Options options("CapiTrain VPN Sniffer");
    options.add_options()
            ("interface-name", "Name of the interface", cxxopts::value<string>()->default_value("en0"))
            ("client-ip", "IP of the client (phone)", cxxopts::value<string>()->default_value(""))
            ("monitor-ip", "IP of the monitor (your IP)", cxxopts::value<string>()->default_value(""))
            ("server-ip", "IP of the server (the VPN server's IP)", cxxopts::value<string>()->default_value(""));
    return options;
}

vector<string> getInterfaceNames() {
    auto interfaces = Tins::NetworkInterface::all();
    vector<string> interfaceNames(interfaces.size());
    transform(interfaces.begin(), interfaces.end(), interfaceNames.begin(), [&](const Tins::NetworkInterface &n) {
        return n.name();
    });
    return interfaceNames;
}

int main(int argc, char *argv[]) {
    cout << "Package sniffer" << endl;

    auto options = createOptions();
    auto parsedOptions = options.parse(argc, argv);

    auto interfaceName = parsedOptions["interface-name"].as<string>();
    auto clientIP = parsedOptions["client-ip"].as<string>();
    auto serverIP = parsedOptions["server-ip"].as<string>();
    auto monitorIP = parsedOptions["monitor-ip"].as<string>();

    cout << "List of available interfaces:" << endl;
    auto interfaceNames = getInterfaceNames();
    for (const auto &existingInterfaceName : interfaceNames) {
        cout << "* " << existingInterfaceName << endl;
    }

    auto hasInterface = find(interfaceNames.begin(), interfaceNames.end(), interfaceName) != interfaceNames.end();
    if (!hasInterface) {
        cout << "Could not find interface " << interfaceName << endl;
        return 0;
    }

    cout << endl;

    cout << "Starting sniffer on interface " << interfaceName << "..." << endl;
    CapiTrain::VPNSniffer sniffer(interfaceName, clientIP, serverIP, monitorIP);
    thread thread([&]() {
        sniffer.start();
    });
    cout << "Sniffer started!" << endl;

    save_packets(sniffer);

    sleep_forever();
}
