#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

string getPackageSource(const IP::address_type& addressType, const TCP &tcp)
{
    return addressType.to_string()
        .append(":")
        .append(to_string(tcp.dport()));
}

bool callback(const PDU &pdu) {
    auto &ip = pdu.rfind_pdu<IP>();
    auto &tcp = pdu.rfind_pdu<TCP>();
    auto src = getPackageSource(ip.src_addr(), tcp);
    auto dest = getPackageSource(ip.dst_addr(), tcp);

    if (src != "92.222.93.179:443" && dest != "92.222.93.179:443")
    {
        return true;
    }

    cout << src << " -> " << dest << endl;

    return true;
}

int main() {
    Sniffer("ens3").sniff_loop(callback);
}