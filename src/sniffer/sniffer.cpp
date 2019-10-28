#include "sniffer.h"
#include "package.h"

#include <sstream>

using namespace CapiTrain;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;


sniffer::sniffer(const std::string &interfaceName) : streamId(0) {
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

rxcpp::observable<package> sniffer::getPackages() const {
    return this->packages.get_observable();
}

void sniffer::on_new_stream(Stream &stream) {
    auto currentStreamId = this->get_next_stream_id();
    this->active_packets[currentStreamId] = 0;
    const Stream::payload_type &payload = stream.client_payload();
    stream.client_data_callback(
            [&, currentStreamId](Stream &stream) {
                this->on_client_data(stream, currentStreamId);
            }
    );
    stream.server_data_callback(
            [&, currentStreamId](Stream &stream) {
                this->on_server_data(stream, currentStreamId);
            }
    );
    stream.stream_closed_callback(
            [&, currentStreamId](Stream &stream) {
                this->on_connection_closed(stream, currentStreamId);
            }
    );
}

void sniffer::on_connection_closed(Stream &stream, long currentStreamId) {
    auto size = this->active_packets[currentStreamId];
    auto clientIp = stream.client_addr_v4().to_string();
    auto serverIp = stream.server_addr_v4().to_string();
    std::cout << "Connection closed (" << serverIp << " -> " << clientIp << "), total size: " << size << std::endl;
    this->active_packets.erase(currentStreamId);
    std::cout << "Active connections:" << this->active_packets.size() << std::endl;
}

void sniffer::on_client_data(Stream &stream, long currentStreamId) {
    auto size = stream.client_payload().size();
    this->active_packets[currentStreamId] = this->active_packets[currentStreamId] + size;
}

void sniffer::on_server_data(Stream &stream, long currentStreamId) {
    auto size = stream.server_payload().size();
    this->active_packets[currentStreamId] = this->active_packets[currentStreamId] + size;
}

long sniffer::get_next_stream_id() {
    if (this->active_packets.empty()) {
        this->streamId = 0;
        return 0;
    }
    return ++this->streamId;
}

