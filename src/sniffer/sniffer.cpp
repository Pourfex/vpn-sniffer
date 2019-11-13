#include "sniffer.h"
#include "package.h"

#include <iostream>
#include <chrono>
#include <utility>

using namespace CapiTrain;

using std::cout;
using std::endl;
using std::string;
using std::make_shared;
using std::move;
using std::chrono::seconds;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::pcap_error;

sniffer::sniffer(string interfaceName, string clientIP, string serverIP)
        : clientIP(move(clientIP)),
          serverIP(move(serverIP)),
          interfaceName(move(interfaceName)) {
}

void sniffer::start() {
    StreamFollower streamFollower;
    streamFollower.new_stream_callback([&](Stream &stream) {
        this->on_new_stream(stream);
    });
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("tcp");
    Sniffer sniffer(interfaceName, config);
    sniffer.sniff_loop([&](PDU &pdu) {
        streamFollower.process_packet(pdu);
        return true;
    });
}

observable<stream_data> sniffer::get_streams() const {
    return this->streams.get_observable();
}

void sniffer::on_new_stream(Stream &stream) {
    cout << "New stream" << endl;

    auto serverIp = stream.server_addr_v4().to_string();

    if (serverIp == this->serverIP) {
        return;
    }

    auto packages = make_shared<subject<package>>();
    auto packages$ = packages->get_observable();
    stream_data streamData{
            .ip = serverIp,
            .packages$ = packages$
    };
    this->streams.get_subscriber().on_next(streamData);

    auto debounceTime = seconds(120);

    packages$
            .skip(1)
            .debounce(debounceTime)
            .subscribe([&, packages](const package &p) {
                cout << "Terminating" << endl;
                packages->get_subscriber().on_completed();
            });

    stream.server_data_callback([&, packages](Stream &stream) {
        this->on_server_data(stream, packages);
    });

    stream.stream_closed_callback([&, packages](Stream &stream) {
        packages->get_subscriber().on_completed();
    });
}

void sniffer::on_server_data(Stream &stream, const shared_ptr<subject<package>> &packages) {
    if (stream.client_addr_v4().to_string() == this->clientIP) {
        return;
    }
    auto size = stream.server_payload().size();
    package package{
            .size = size
    };
    packages->get_subscriber().on_next(package);
}


