#include "sniffer.h"
#include "package.h"
#include <sstream>

using namespace CapiTrain;

using std::cout;
using std::cerr;
using std::endl;
using std::bind;
using std::string;
using std::to_string;
using std::ostringstream;
using std::exception;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::TCPIP::Stream;
using Tins::TCPIP::Stream;

string client_endpoint(const Stream& stream) {
    ostringstream output;
    // Use the IPv4 or IPv6 address depending on which protocol the
    // connection uses
    if (stream.is_v6()) {
        output << stream.client_addr_v6();
    }
    else {
        output << stream.client_addr_v4();
    }
    output << ":" << stream.client_port();
    return output.str();
}

// Convert the server endpoint to a readable string
string server_endpoint(const Stream& stream) {
    ostringstream output;
    if (stream.is_v6()) {
        output << stream.server_addr_v6();
    }
    else {
        output << stream.server_addr_v4();
    }
    output << ":" << stream.server_port();
    return output.str();
}

// Concat both endpoints to get a readable stream identifier
string stream_identifier(const Stream& stream) {
    ostringstream output;
    output << client_endpoint(stream) << " - " << server_endpoint(stream);
    return output.str();
}

// Whenever there's new client data on the stream, this callback is executed.
void on_client_data(Stream& stream) {
    // Construct a string out of the contents of the client's payload
    string data(stream.client_payload().begin(), stream.client_payload().end());

    // Now print it, prepending some information about the stream
    cout << client_endpoint(stream) << " >> "
         << server_endpoint(stream) << ": " << data.size() << endl;
}

// Whenever there's new server data on the stream, this callback is executed.
// This does the same thing as on_client_data
void on_server_data(Stream& stream) {
    string data(stream.server_payload().begin(), stream.server_payload().end());
    cout << server_endpoint(stream) << " >> "
         << client_endpoint(stream) << ": " << data.size() << endl;
}

// When a connection is closed, this callback is executed.
void on_connection_closed(Stream& stream) {
    cout << "[+] Connection closed: " << stream_identifier(stream) << endl;
}

sniffer::sniffer(const std::string &interfaceName) {
    this->tinsSniffer = std::make_unique<Tins::Sniffer>(interfaceName);
}

void sniffer::start() {
    Tins::TCPIP::StreamFollower streamFollower;
    streamFollower.new_stream_callback([&](Stream &stream) {
        this->sniffCallback(stream);
    });
    tinsSniffer->sniff_loop([&](PDU &pdu) {
        streamFollower.process_packet(pdu);
        return true;
    });
}

void sniffer::sniffCallback(Stream &stream) {
    const Stream::payload_type &payload = stream.client_payload();

    cout << "[+] New connection " << stream_identifier(stream) << endl;

    // Now configure the callbacks on it.
    // First, we want on_client_data to be called every time there's new client data
    stream.client_data_callback(&on_client_data);

    // Same thing for server data, but calling on_server_data
    stream.server_data_callback(&on_server_data);

    // When the connection is closed, call on_connection_closed
    stream.stream_closed_callback(&on_connection_closed);
}

rxcpp::observable<package> sniffer::getPackages() const {
    return this->packages.get_observable();
}

