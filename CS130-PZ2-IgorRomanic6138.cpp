#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <ctime>
#include <pcap.h>
#include <algorithm>
#include <memory>
#include <iomanip>
#include <csignal>

using namespace std;


class PaketSniffer {
public:
    virtual void izlistajInterfejse() = 0;
    virtual void odaberiInterfejs(int index) = 0;
    virtual void start() = 0;
    virtual void zaustavi() = 0;
    virtual ~PaketSniffer() {};
};

class PcapSniffer : public PaketSniffer {
private:
    vector<string> interfejsNaziv;
    vector<pcap_if_t*> interfejsPtr;
    pcap_if_t* izabraniInterfejs;
    pcap_t* handle;
    ofstream fajlLog;
    int brojPaketa = 0;

public:
    void izlistajInterfejse() override {
        pcap_if_t* sviUredjaji;
        char errorBafer[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&sviUredjaji, errorBafer) == -1) 
        {
            throw runtime_error("Greska: " + string(errorBafer));
        }

        int index = 0;
        for (pcap_if_t* d = sviUredjaji; d != nullptr; d = d->next) 
        {
            string name = d->name;
            string friendly = d->description;
            interfejsPtr.push_back(d);
            interfejsNaziv.push_back(name);
            cout << "[" << index++ << "] " << friendly << endl;
        }

        if (interfejsNaziv.empty()) 
        {
            throw runtime_error("Nisu pronadjeni interfejsi...");
        }
    }

    void odaberiInterfejs(int index) override {
        if (index < 0 || index >= static_cast<int>(interfejsPtr.size())) 
        {
            throw out_of_range("Odabrani index nije validan...");
        }
        else
        {
            izabraniInterfejs = interfejsPtr[index];
        }
    }

    void start() override {
        char errorBafer[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(izabraniInterfejs->name, 65536, 1, 1000, errorBafer);

        if (!handle) 
        {
            throw runtime_error("Greska: " + string(errorBafer));
        }

        fajlLog.open("paketi.txt");
        if (!fajlLog.is_open())
        {
            throw runtime_error("Greska prilikom otvaranja fajla...");
        }

        cout << "\nPokrenuto sniff-ovanje: " << "\n";

        pcap_loop(handle, 0, paketHandler, reinterpret_cast<u_char*>(this));
    }

    void zaustavi() override
    {
        if(handle)
        {
            pcap_breakloop(handle);
        }

        if(fajlLog.is_open())
        {
            fajlLog.flush();
            fajlLog.close();
        }

        cout << "Paketi sacuvani u paketi.txt fajlu..." << endl;
    }

    static void paketHandler(u_char* podaci, const struct pcap_pkthdr* header, const u_char* paket) 
    {
        PcapSniffer* sniffer = reinterpret_cast<PcapSniffer*>(podaci);
        sniffer->brojPaketa++;

        time_t rawtime = header->ts.tv_sec;
        struct tm* timeinfo = localtime(&rawtime);

        char timeStr[64];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);

        string protokol = sniffer->odrediProtokol(paket);

        cout << sniffer->brojPaketa << "|" << timeStr << " | Duzina: " << header->len << " bajtova | Protokol: " << protokol << endl;

        sniffer->fajlLog << sniffer->brojPaketa << "|" << timeStr << " | Duzina: " << header->len << " bajtova | Protokol: " << protokol << endl;
    }

    string odrediProtokol(const u_char* paket) 
    {
        const int ETH_HEADER_LEN = 14;
        const u_char* ipHeader = paket + ETH_HEADER_LEN;
        u_char protokol = ipHeader[9];

        switch (protokol) 
        {
        case 6: 
            return "TCP";
        case 17: 
            return "UDP";
        case 1: 
            return "ICMP";
        case 51:
            return "AH";
        case 41:
            return "IPv6";
        case 58:
            return "ICMPv6";
        default: return "Other";
        }
    }

    ~PcapSniffer() {

        zaustavi();

        if(interfejsPtr.empty())
        {
            pcap_freealldevs(interfejsPtr[0]);
        }
    }
};

int main() {
    try {
        cout << "Izaberite mrezni interfejs:" << endl;

        PcapSniffer sniffer;

        sniffer.izlistajInterfejse();

        cout << "\n>";
        int index;
        cin >> index;

        sniffer.odaberiInterfejs(index);
        sniffer.start();
    }
    catch (const exception& e) {
        cerr << "Greska: " << e.what() << endl;
        return 1;
    }

    return 0;
}