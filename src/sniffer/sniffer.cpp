#include "sniffer.h"
#include "package.h"

#include <sstream>

using namespace CapiTrain;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;

sniffer::sniffer(const std::string &interfaceName) {
    this->tinsSniffer = std::make_unique<Tins::Sniffer>(interfaceName);
}

void sniffer::start() {
    Tins::TCPIP::StreamFollower streamFollower;
    streamFollower.new_stream_callback([&](Stream &stream) {
        this->on_new_stream(stream);
    });
    tinsSniffer->sniff_loop([&](PDU &pdu) {
        streamFollower.process_packet(pdu);
        return true;
    });
}

rxcpp::observable<package> sniffer::get_packages() const {
    return this->packages.get_observable();
}

void sniffer::on_new_stream(Stream &stream) {
    stream.server_data_callback([&](Stream &stream) { this->on_server_data(stream); });
}

void sniffer::on_server_data(Stream &stream) {
    // TODO set Monitor IP as an environment variable
    if (stream.client_addr_v4().to_string() == "109.10.173.127") {
        return;
    }
    auto size = stream.server_payload().size();
    package package;
    package.size = size;
    package.dest = stream.server_addr_v4().to_string();
    auto subscriber = this->packages.get_subscriber();
    subscriber.on_next(package);
}


