#include "sniffer.h"
#include "package.h"

#include <sstream>

using namespace CapiTrain;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::Utils::resolve_domain;

std::string rdsnToHostName(std::string host)
{
    size_t result;
    std::map<std::string, std::string> searches = {
            {"facebook", "facebook"},
            {"fbcdn", "facebook"},
            {"1e100.net", "Google"},
            {"kgb.emn", "maileleves.emn"}
    };

    for (auto const &x : searches)
    {
        if (x.first == "fbcdn")
        {
            result = host.find("instagram");
            if (result != std::string::npos)
            {
                return "instagram";
            }
        }
        result = host.find(x.first);
        if (result != std::string::npos)
        {
            return x.second;
        }
    }

    return host;
}

std::string exec(const char *cmd)
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    return result;
}

sniffer::sniffer(const std::string &interfaceName) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("tcp");
    this->tinsSniffer = std::make_unique<Tins::Sniffer>(interfaceName, config);
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
    if (stream.server_addr_v4().to_string() == "92.222.93.179") {
        return;
    }
    std::string ipString = stream.server_addr_v4().to_string();
    std::string domain = rdsnToHostName(exec(("host " + ipString).c_str()));

    std::cout << "New stream: " << stream.server_addr_v4() << " * Coming from "<< domain << std::endl;

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
    package.port = stream.server_port();
    auto subscriber = this->packages.get_subscriber();
    subscriber.on_next(package);
}






