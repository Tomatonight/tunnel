#include "subnet_platform.h"
#include "third_party/nlohmann/json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
bool equal_route(const ImportedRoute& a, const ImportedRoute& b) {
    return a.tunnel == b.tunnel && a.prefix == b.prefix && a.source == b.source;
}
bool includes_route(const std::vector<ImportedRoute>& entries, const ImportedRoute& r) {
    for (const auto& e : entries) if (equal_route(e, r)) return true;
    return false;
}
void validate_prefix(const Network& prefix) {
    if (!prefix.prefix || !(Network::parse(prefix.str()) == prefix))
        throw std::invalid_argument("subnet routes require a canonical non-default prefix");
}
std::string trim(std::string value) {
    const auto start = value.find_first_not_of(" \r\n\t"), end = value.find_last_not_of(" \r\n\t");
    return start == std::string::npos ? std::string() : value.substr(start, end - start + 1);
}
void safe_interface(const std::string& name) {
    if (name.empty() || name.size() > 63) throw std::runtime_error("invalid route interface name");
    for (char c : name) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
        throw std::runtime_error("unsupported route interface name");
}
#ifndef __ANDROID__
std::string command(const std::vector<std::string>& args, const std::string& input = {}) {
    if (args.empty()) throw std::logic_error("empty system command");
#ifdef _WIN32
    if (!input.empty()) throw std::logic_error("Windows command stdin is not supported");
    std::wstring line;
    for (const auto& arg : args) {
        if (!line.empty()) line += L' ';
        line += L'"'; unsigned slashes = 0;
        for (unsigned char c : arg) {
            if (c == '\\') { ++slashes; continue; }
            line.append(slashes * (c == '"' ? 2 : 1), L'\\'); slashes = 0;
            if (c == '"') line += L'\\';
            line += wchar_t(c);
        }
        line.append(slashes * 2, L'\\'); line += L'"';
    }
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE}; HANDLE read = nullptr, write = nullptr;
    if (!CreatePipe(&read, &write, &security, 0)) throw std::runtime_error("system command pipe failed");
    SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE; startup.hStdOutput = write; startup.hStdError = write;
    HANDLE null_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr);
    startup.hStdInput = null_input;
    PROCESS_INFORMATION process{};
    const bool created = CreateProcessW(nullptr, &line[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
    CloseHandle(write); if (null_input != INVALID_HANDLE_VALUE) CloseHandle(null_input);
    if (!created) { CloseHandle(read); throw std::runtime_error("cannot start subnet configuration tool"); }
    std::string output; bool timed_out = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    for (;;) {
        DWORD count = 0;
        if (PeekNamedPipe(read, nullptr, 0, nullptr, &count, nullptr) && count) {
            char buffer[4096]; DWORD size = 0;
            if (ReadFile(read, buffer, std::min<DWORD>(count, sizeof(buffer)), &size, nullptr)) {
                if (output.size() + size <= 1048576) output.append(buffer, size);
                else { timed_out = true; break; }
            }
            continue;
        }
        if (WaitForSingleObject(process.hProcess, 10) == WAIT_OBJECT_0) break;
        if (std::chrono::steady_clock::now() > deadline) { timed_out = true; break; }
    }
    if (timed_out) { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 1000); }
    DWORD code = 1; GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(read); CloseHandle(process.hThread); CloseHandle(process.hProcess);
    if (timed_out || code) throw std::runtime_error("subnet system command failed: " + args.front() + ": " + trim(output).substr(0, 400));
    return output;
#else
    FILE* in = std::tmpfile(); FILE* out = std::tmpfile();
    if (!in || !out) { if (in) std::fclose(in); if (out) std::fclose(out); throw std::runtime_error("subnet command temporary stream failed"); }
    if (std::fwrite(input.data(), 1, input.size(), in) != input.size() || std::fflush(in)) {
        std::fclose(in); std::fclose(out); throw std::runtime_error("subnet command input failed");
    }
    std::rewind(in);
    std::vector<char*> argv; for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str())); argv.push_back(nullptr);
    const auto child = fork();
    if (child == 0) {
        if (dup2(fileno(in), STDIN_FILENO) < 0 || dup2(fileno(out), STDOUT_FILENO) < 0 || dup2(fileno(out), STDERR_FILENO) < 0) _exit(126);
        execvp(argv[0], argv.data()); _exit(127);
    }
    if (child < 0) { std::fclose(in); std::fclose(out); throw std::runtime_error("subnet command fork failed"); }
    int status = 0; bool timed_out = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    for (;;) {
        const auto done = waitpid(child, &status, WNOHANG);
        if (done == child) break;
        if ((done < 0 && errno != EINTR) || std::chrono::steady_clock::now() > deadline) {
            timed_out = true; kill(child, SIGKILL); while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} break;
        }
        usleep(10000);
    }
    std::rewind(out); std::string output; char buffer[4096]; std::size_t size;
    while ((size = std::fread(buffer, 1, sizeof(buffer), out)) != 0 && output.size() < 1048576) output.append(buffer, size);
    std::fclose(in); std::fclose(out);
    if (timed_out || !WIFEXITED(status) || WEXITSTATUS(status))
        throw std::runtime_error("subnet system command failed: " + args.front() + ": " + trim(output).substr(0, 400));
    return output;
#endif
}
#endif
IpAddress sockaddr_ip(const sockaddr* address) { return Endpoint::from_sockaddr(address).ip; }
std::vector<Network> interface_networks(const std::string& exclude, std::vector<IpAddress>* addresses = nullptr) {
    std::vector<Network> result;
#ifdef _WIN32
    ULONG size = 16384; std::vector<unsigned char> buffer(size); ULONG status;
    do {
        buffer.resize(size);
        status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    } while (status == ERROR_BUFFER_OVERFLOW && size <= 4 * 1024 * 1024);
    if (status != NO_ERROR) throw std::runtime_error("cannot inspect existing interface networks");
    const std::wstring name(exclude.begin(), exclude.end());
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter; adapter = adapter->Next) {
        if (adapter->FriendlyName && name == adapter->FriendlyName) continue;
        for (auto* entry = adapter->FirstUnicastAddress; entry; entry = entry->Next)
            if (entry->Address.lpSockaddr && (entry->Address.lpSockaddr->sa_family == AF_INET || entry->Address.lpSockaddr->sa_family == AF_INET6)) {
                const auto ip = sockaddr_ip(entry->Address.lpSockaddr);
                if (addresses) addresses->push_back(ip);
                result.push_back(Network::parse(ip.str() + "/" + std::to_string(entry->OnLinkPrefixLength)));
            }
    }
#else
    ifaddrs* list = nullptr;
    if (getifaddrs(&list)) throw std::runtime_error("cannot inspect existing interface networks");
    try {
        for (auto* entry = list; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || !entry->ifa_netmask || exclude == entry->ifa_name ||
                (entry->ifa_addr->sa_family != AF_INET && entry->ifa_addr->sa_family != AF_INET6)) continue;
            auto address = sockaddr_ip(entry->ifa_addr), mask = sockaddr_ip(entry->ifa_netmask);
            if (addresses) addresses->push_back(address);
            unsigned bits = 0; bool zero = false;
            for (unsigned i = 0; i < (address.family == 4 ? 4u : 16u); ++i)
                for (int bit = 7; bit >= 0; --bit) {
                    if (mask.bytes[i] & (1 << bit)) { if (zero) throw std::runtime_error("noncontiguous interface netmask"); ++bits; }
                    else zero = true;
                }
            result.push_back(Network::parse(address.str() + "/" + std::to_string(bits)));
        }
    } catch (...) { freeifaddrs(list); throw; }
    freeifaddrs(list);
#endif
    return result;
}
}

std::vector<ImportedRoute> checked_imports(const Configure& config, const std::vector<NetworkConfig>& active,
                                         const std::vector<ImportedRoute>& requested) {
    if (requested.size() > 256) throw std::invalid_argument("too many imported routes");
    std::vector<ImportedRoute> result = requested;
    std::sort(result.begin(), result.end(), [](const ImportedRoute& a, const ImportedRoute& b) { return a.prefix < b.prefix; });
    for (std::size_t i = 0; i < result.size(); ++i) {
        const auto& r = result[i]; validate_prefix(r.prefix);
        bool member = false;
        for (const auto& n : active) if (n.tunnel == r.tunnel && n.tunnel_ip == r.source && n.tunnel.usable_host(r.source)) member = true;
        if (!member || r.source.family != r.prefix.address.family) throw std::invalid_argument("imported route needs an active local source in its tunnel");
#if defined(_WIN32) || defined(__ANDROID__)
        unsigned sources = 0;
        for (const auto& n : active) if (!n.tunnel_ip.unspecified() && n.tunnel_ip.family == r.source.family) ++sources;
        if (sources > 1) throw std::invalid_argument("this platform requires one active tunnel address per IP family when importing subnets");
#endif
        for (const auto& n : config.networks) if (r.prefix.overlaps(n.tunnel)) throw std::invalid_argument("imported route overlaps a virtual network");
        for (std::size_t j = 0; j < i; ++j) if (r.prefix.overlaps(result[j].prefix)) throw std::invalid_argument("overlapping imported routes");
        auto protects = [&](const Endpoint& e) { return e.port && !e.ip.unspecified() && r.prefix.contains(e.ip); };
        if (protects(config.listen.address) || (config.address_server.enabled && protects(config.address_server.address)))
            throw std::invalid_argument("imported route covers a local public endpoint");
        for (const auto& p : config.peers) if (protects(p.address)) throw std::invalid_argument("imported route covers a peer endpoint");
        for (const auto& s : config.address_clients) if (protects(s.address)) throw std::invalid_argument("imported route covers an address server endpoint");
    }
    return result;
}
bool same_imports(const std::vector<ImportedRoute>& a, const std::vector<ImportedRoute>& b) {
    if (a.size() != b.size()) return false;
    for (const auto& r : a) if (!includes_route(b, r)) return false;
    return true;
}
std::vector<IpAddress> subnet_probe_addresses(const Network& prefix, const std::vector<IpAddress>& local_addresses) {
    validate_prefix(prefix);
    std::vector<IpAddress> result;
    auto candidate = prefix.address;
    // At most the local-address count plus a small number of probes is needed.
    // /31 and /127 are point-to-point ranges; /32 and /128 use their sole host.
    for (std::size_t attempt = 0; attempt < local_addresses.size() + 18 && prefix.contains(candidate); ++attempt) {
        const bool anycast = candidate.family == 6 && prefix.prefix < 127 && candidate == prefix.address;
        if (!anycast && prefix.usable_host(candidate) &&
            std::find(local_addresses.begin(), local_addresses.end(), candidate) == local_addresses.end()) {
            result.push_back(candidate);
            if (result.size() == 16) break;
        }
        int byte = candidate.family == 4 ? 3 : 15;
        while (byte >= 0 && ++candidate.bytes[byte] == 0) --byte;
        if (byte < 0) break;
    }
    return result;
}

struct SubnetPlatform::Impl {
    std::string name, token;
    Configure config;
    std::vector<ImportedRoute> routes;
    std::vector<AdvertisedRoute> exports;
    bool nat_owned = false;
    std::map<std::string, std::string> forwarding;
#ifdef _WIN32
    NET_LUID luid{};
    std::vector<MIB_IPINTERFACE_ROW> forwarding_rows;
    Network nat_prefix;
#elif defined(__APPLE__)
    std::string pf_token;
#endif
    Impl(const std::string& n, const Configure& c) : name(n), config(c) {
        safe_interface(name); static std::atomic<unsigned> sequence{0};
#ifdef _WIN32
        token = "tunnel_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(++sequence);
        const std::wstring wide(name.begin(), name.end());
        if (ConvertInterfaceAliasToLuid(wide.c_str(), &luid) != NO_ERROR) throw std::runtime_error("subnet interface lookup failed");
#else
        token = "tunnel_" + std::to_string(getpid()) + "_" + std::to_string(++sequence);
#endif
    }
#if !defined(__ANDROID__)
#ifdef _WIN32
    NET_LUID egress_interface(const Network& prefix, const std::vector<IpAddress>& local_addresses) {
#else
    std::string egress_interface(const Network& prefix, const std::vector<IpAddress>& local_addresses) {
#endif
        for (const auto& address : subnet_probe_addresses(prefix, local_addresses)) {
#ifdef _WIN32
            Endpoint target; target.ip = address; int length; const auto storage = target.sockaddr_value(&length);
            MIB_IPFORWARD_ROW2 route{}; SOCKADDR_INET source{};
            if (GetBestRoute2(nullptr, 0, nullptr, reinterpret_cast<const SOCKADDR_INET*>(&storage), 0, &route, &source) != NO_ERROR ||
                route.InterfaceLuid.Value == luid.Value || route.Loopback) continue;
            MIB_IF_ROW2 interface_row{}; interface_row.InterfaceLuid = route.InterfaceLuid;
            if (GetIfEntry2(&interface_row) != NO_ERROR || interface_row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            return route.InterfaceLuid;
#else
            std::string output;
            try {
#ifdef __APPLE__
                const auto info = command({"/sbin/route", "-n", "get", address.family == 4 ? "-inet" : "-inet6", address.str()});
                const auto marker = info.find("interface:");
                if (marker == std::string::npos) continue;
                const auto end = info.find('\n', marker); output = trim(info.substr(marker + 10, end - marker - 10));
                if (output == "lo0") continue;
#else
                const auto route = nlohmann::json::parse(command({"ip", "-j", address.family == 4 ? "-4" : "-6", "route", "get", address.str()}));
                if (!route.is_array() || route.empty() || !route[0].count("dev") ||
                    route[0].value("type", std::string("unicast")) != "unicast") continue;
                output = route[0]["dev"].get<std::string>();
                if (output == "lo") continue;
#endif
            } catch (const std::exception&) { continue; }
            safe_interface(output);
            if (output != name) return output;
#endif
        }
        throw std::runtime_error("subnet export has no non-local physical egress route: " + prefix.str());
    }
#endif
    void route(const ImportedRoute& r, bool add) {
#if defined(__ANDROID__)
        (void)r; (void)add; throw std::runtime_error("Android routes require the VpnService host callback");
#elif defined(_WIN32)
        MIB_IPFORWARD_ROW2 row; InitializeIpForwardEntry(&row); row.InterfaceLuid = luid;
        row.DestinationPrefix.Prefix.si_family = r.prefix.address.family == 4 ? AF_INET : AF_INET6;
        row.NextHop.si_family = row.DestinationPrefix.Prefix.si_family;
        if (r.prefix.address.family == 4) std::memcpy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr, r.prefix.address.bytes.data(), 4);
        else std::memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, r.prefix.address.bytes.data(), 16);
        row.DestinationPrefix.PrefixLength = static_cast<UINT8>(r.prefix.prefix); row.Metric = 7;
        row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
        if (add) {
            PMIB_IPFORWARD_TABLE2 table = nullptr;
            if (GetIpForwardTable2(row.NextHop.si_family, &table) != NO_ERROR) throw std::runtime_error("cannot inspect existing routes");
            bool conflict = false;
            for (ULONG i = 0; i < table->NumEntries; ++i) {
                const auto& entry = table->Table[i]; const auto& old = entry.DestinationPrefix;
                if (!old.PrefixLength) continue; // An ordinary default route is expected.
                const auto prefix = Network::parse(sockaddr_ip(reinterpret_cast<const sockaddr*>(&old.Prefix)).str() + "/" + std::to_string(old.PrefixLength));
                bool ours = false;
                if (entry.InterfaceLuid.Value == luid.Value && entry.Metric == 7 && entry.Protocol == static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT))
                    for (const auto& installed : routes) if (installed.prefix == prefix) ours = true;
                if (!ours && prefix.overlaps(r.prefix)) conflict = true;
            }
            FreeMibTable(table);
            if (conflict) throw std::runtime_error("refusing to replace an existing subnet route: " + r.prefix.str());
        }
        const auto status = add ? CreateIpForwardEntry2(&row) : DeleteIpForwardEntry2(&row);
        if (status != NO_ERROR) throw std::runtime_error("subnet route update failed: " + std::to_string(status));
#elif defined(__APPLE__)
        // route add fails on an existing destination; never use change/replace.
        if (add) {
            const auto listing = command({"/usr/sbin/netstat", "-n", "-r", "-f", r.prefix.address.family == 4 ? "inet" : "inet6"});
            std::istringstream lines(listing); std::string line;
            while (std::getline(lines, line)) {
                std::istringstream fields(line); std::string destination, gateway, flags, interface_name;
                if (!(fields >> destination >> gateway >> flags >> interface_name) || destination == "Destination" || destination == "default") continue;
                auto slash = destination.find('/');
                std::string address = destination.substr(0, slash), mask = slash == std::string::npos ? "" : destination.substr(slash + 1);
                const auto zone = address.find('%'); if (zone != std::string::npos) address.resize(zone);
                if (r.prefix.address.family == 4) {
                    const auto parts = 1 + std::count(address.begin(), address.end(), '.');
                    if (mask.empty()) mask = std::to_string(parts * 8);
                    for (unsigned part = static_cast<unsigned>(parts); part < 4; ++part) address += ".0";
                } else if (mask.empty()) mask = "128";
                const auto prefix = Network::parse(address + "/" + mask);
                if (!prefix.prefix) continue;
                bool ours = false;
                if (interface_name == name) for (const auto& installed : routes)
                    if (installed.prefix.contains(prefix.address) && installed.prefix.prefix <= prefix.prefix) ours = true;
                if (!ours && prefix.overlaps(r.prefix))
                    throw std::runtime_error("imported subnet overlaps an existing system route: " + prefix.str());
            }
        }
        command({"/sbin/route", "-n", add ? "add" : "delete", r.prefix.address.family == 4 ? "-inet" : "-inet6",
                 "-net", r.prefix.str(), "-interface", name, "-ifa", r.source.str()});
#else
        const std::string family = r.prefix.address.family == 4 ? "-4" : "-6";
        if (add) {
            auto existing = nlohmann::json::parse(command({"ip", "-j", family, "route", "show", "table", "all"}));
            for (const auto& entry : existing) {
                if (!entry.count("dst")) continue;
                auto destination = entry.at("dst").get<std::string>();
                if (destination == "default") continue;
                if (destination.find('/') == std::string::npos) destination += r.prefix.address.family == 4 ? "/32" : "/128";
                const auto prefix = Network::parse(destination);
                if (!prefix.prefix) continue;
                bool ours = false;
                if (entry.value("dev", std::string()) == name && entry.value("metric", 0) == 7)
                    for (const auto& installed : routes) if (installed.prefix == prefix) ours = true;
                if (!ours && prefix.overlaps(r.prefix))
                    throw std::runtime_error("imported subnet overlaps an existing system route: " + prefix.str());
            }
        }
        command({"ip", family, "route", add ? "add" : "del", r.prefix.str(), "dev", name, "src", r.source.str(), "proto", "186", "metric", "7"});
#endif
    }
    void set_routes(const std::vector<ImportedRoute>& next) {
        if (same_imports(routes, next)) return;
        const auto occupied = interface_networks(name);
        for (const auto& r : next) if (!includes_route(routes, r))
            for (const auto& n : occupied) if (r.prefix.overlaps(n))
                throw std::runtime_error("imported subnet overlaps an existing interface network: " + r.prefix.str());
        for (std::size_t i = 0; i < routes.size();) {
            if (includes_route(next, routes[i])) { ++i; continue; }
            route(routes[i], false); routes.erase(routes.begin() + i);
        }
        for (const auto& r : next) if (!includes_route(routes, r)) { route(r, true); routes.push_back(r); }
    }
#ifndef _WIN32
    std::string setting(const std::string& path) {
#ifdef __APPLE__
        return trim(command({"/usr/sbin/sysctl", "-n", path}));
#else
        std::ifstream input(path.c_str()); std::string value;
        if (!(input >> value)) throw std::runtime_error("cannot read forwarding setting: " + path);
        return value;
#endif
    }
    void write_setting(const std::string& path, const std::string& value) {
#ifdef __APPLE__
        command({"/usr/sbin/sysctl", "-w", path + "=" + value});
#else
        std::ofstream out(path.c_str()); out << value << '\n'; out.flush();
        if (!out) throw std::runtime_error("cannot change forwarding setting: " + path);
#endif
    }
    void enable(const std::string& path) {
        if (forwarding.count(path)) return;
        const auto before = setting(path);
        if (before != "0" && before != "1") throw std::runtime_error("invalid forwarding setting");
        if (before == "0") { forwarding[path] = before; write_setting(path, "1"); }
    }
#endif
    void restore_forwarding() {
#ifdef _WIN32
        for (std::size_t i = 0; i < forwarding_rows.size();) {
            auto row = forwarding_rows[i];
            const auto status = GetIpInterfaceEntry(&row);
            if (status != NO_ERROR && status != ERROR_NOT_FOUND && status != ERROR_FILE_NOT_FOUND && status != ERROR_DEVICE_NOT_CONNECTED)
                throw std::runtime_error("cannot inspect interface forwarding during cleanup: " + std::to_string(status));
            if (status == NO_ERROR && row.ForwardingEnabled) {
                row.ForwardingEnabled = forwarding_rows[i].ForwardingEnabled;
                if (SetIpInterfaceEntry(&row) != NO_ERROR) throw std::runtime_error("cannot restore interface forwarding");
            }
            forwarding_rows.erase(forwarding_rows.begin() + i);
        }
#else
        for (auto it = forwarding.begin(); it != forwarding.end();) {
            // Do not override a value somebody has changed since our enable.
            if (setting(it->first) == "1") write_setting(it->first, it->second);
            it = forwarding.erase(it);
        }
#endif
    }
#ifdef _WIN32
    void enable_interface(NET_LUID id, ADDRESS_FAMILY family) {
        for (const auto& old : forwarding_rows) if (old.InterfaceLuid.Value == id.Value && old.Family == family) return;
        MIB_IPINTERFACE_ROW row; InitializeIpInterfaceEntry(&row); row.InterfaceLuid = id; row.Family = family;
        if (GetIpInterfaceEntry(&row) != NO_ERROR) throw std::runtime_error("cannot inspect interface forwarding");
        if (!row.ForwardingEnabled) {
            forwarding_rows.push_back(row); row.ForwardingEnabled = TRUE;
            if (SetIpInterfaceEntry(&row) != NO_ERROR) throw std::runtime_error("cannot enable interface forwarding");
        }
    }
    std::string powershell(const std::string& script) {
        wchar_t directory[MAX_PATH]; const auto size = GetSystemDirectoryW(directory, MAX_PATH);
        if (!size || size >= MAX_PATH) throw std::runtime_error("Windows system directory unavailable");
        std::string executable; for (unsigned i = 0; i < size; ++i) {
            if (directory[i] > 127) throw std::runtime_error("non-ASCII Windows system directory is unsupported");
            executable += char(directory[i]);
        }
        return command({executable + "\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; " + script});
    }
#endif
    void remove_nat() {
        if (!nat_owned) return;
#if defined(__ANDROID__)
        throw std::runtime_error("Android subnet publishing is unsupported");
#elif defined(_WIN32)
        powershell("$n=Get-NetNat -Name '" + token + "' -ErrorAction Stop; if ($n.InternalIPInterfaceAddressPrefix -ne '" + nat_prefix.str() +
            "') { throw 'Owned NAT instance changed; refusing removal' }; Remove-NetNat -Name '" + token + "' -Confirm:$false -ErrorAction Stop");
#elif defined(__APPLE__)
        command({"/sbin/pfctl", "-a", "com.apple/" + token, "-f", "-"}, "\n");
#else
        command({"nft", "delete", "table", "inet", token});
#endif
        nat_owned = false;
    }
    void set_exports(const std::vector<AdvertisedRoute>& next) {
        bool same = exports.size() == next.size();
        for (const auto& r : next) {
            bool found = false;
            for (const auto& old : exports) if (old.tunnel == r.tunnel && old.prefix == r.prefix && old.snat == r.snat) found = true;
            if (!found) same = false;
        }
        if (same && (!next.empty() || (!nat_owned && forwarding.empty()
#ifdef _WIN32
                                     && forwarding_rows.empty()
#elif defined(__APPLE__)
                                     && pf_token.empty()
#endif
                                     ))) return;
        if (next.empty()) {
            remove_nat(); restore_forwarding(); exports.clear();
#ifdef __APPLE__
            if (!pf_token.empty()) { command({"/sbin/pfctl", "-X", pf_token}); pf_token.clear(); }
#endif
            return;
        }
        if (next.size() > 64) throw std::invalid_argument("too many subnet exports");
        for (const auto& r : next) {
            validate_prefix(r.prefix);
            if (r.tunnel.address.family != r.prefix.address.family) throw std::invalid_argument("subnet export address family mismatch");
        }
#if !defined(__ANDROID__)
        std::vector<IpAddress> local_addresses;
        interface_networks("", &local_addresses);
#endif
#if defined(__ANDROID__)
        throw std::runtime_error("Android supports subnet access only; subnet publishing requires a desktop gateway");
#elif defined(_WIN32)
        bool has_nat = false; Network prefix;
        for (const auto& r : next) if (r.snat) {
            if (r.tunnel.address.family != 4) throw std::runtime_error("Windows WinNAT subnet exports support IPv4 only");
            if (has_nat && !(prefix == r.tunnel)) throw std::runtime_error("Windows WinNAT supports only one internal tunnel prefix");
            prefix = r.tunnel; has_nat = true;
        }
        if (has_nat) for (const auto& r : next) if (!r.snat && r.tunnel == prefix)
            throw std::runtime_error("Windows WinNAT cannot mix SNAT and routed exports in one tunnel prefix");
        if (nat_owned && (!has_nat || !(nat_prefix == prefix))) remove_nat();
        if (has_nat && !nat_owned) {
            powershell("if (@(Get-NetNat -ErrorAction Stop).Count -ne 0) { throw 'An existing WinNAT instance prevents private subnet NAT' }; "
                "New-NetNat -Name '" + token + "' -InternalIPInterfaceAddressPrefix '" + prefix.str() + "' -ErrorAction Stop | Out-Null");
            nat_owned = true; nat_prefix = prefix;
        }
        for (const auto& r : next) {
            const auto output = egress_interface(r.prefix, local_addresses);
            const auto family = ADDRESS_FAMILY(r.prefix.address.family == 4 ? AF_INET : AF_INET6);
            enable_interface(luid, family); enable_interface(output, family);
        }
#elif defined(__APPLE__)
        std::ostringstream rules;
        for (const auto& r : next) {
            const auto output = egress_interface(r.prefix, local_addresses);
            enable(r.prefix.address.family == 4 ? "net.inet.ip.forwarding" : "net.inet6.ip6.forwarding");
            if (r.snat) rules << "nat on \"" << output << "\" " << (r.prefix.address.family == 4 ? "inet" : "inet6")
                << " from " << r.tunnel.str() << " to " << r.prefix.str() << " -> (\"" << output << "\")\n";
        }
        if (!rules.str().empty()) {
            const auto active = command({"/sbin/pfctl", "-sn"});
            if (active.find("nat-anchor \"com.apple/*\"") == std::string::npos)
                throw std::runtime_error("macOS requires the existing PF nat-anchor com.apple/*; the main PF rules will not be replaced");
            command({"/sbin/pfctl", "-a", "com.apple/" + token, "-n", "-f", "-"}, rules.str());
            if (pf_token.empty()) {
                const auto enabled = command({"/sbin/pfctl", "-E"}); const auto begin = enabled.find("Token : ");
                if (begin == std::string::npos) throw std::runtime_error("macOS PF did not return an enable reference token");
                auto value = trim(enabled.substr(begin + 8)); value = value.substr(0, value.find_first_not_of("0123456789"));
                if (value.empty()) throw std::runtime_error("macOS PF returned an invalid reference token");
                pf_token = value;
            }
            command({"/sbin/pfctl", "-a", "com.apple/" + token, "-f", "-"}, rules.str()); nat_owned = true;
        } else remove_nat();
#else
        std::ostringstream rules;
        if (nat_owned) rules << "delete table inet " << token << "\n";
        rules << "create table inet " << token << "\n"
              << "add chain inet " << token << " forward { type filter hook forward priority -5; policy accept; }\n"
              << "add chain inet " << token << " postrouting { type nat hook postrouting priority 100; policy accept; }\n";
        for (const auto& r : next) {
            const auto family = r.prefix.address.family == 4 ? std::string("ip") : std::string("ip6");
            const auto output = egress_interface(r.prefix, local_addresses);
            if (r.prefix.address.family == 4) {
                enable("/proc/sys/net/ipv4/conf/" + name + "/forwarding"); enable("/proc/sys/net/ipv4/conf/" + output + "/forwarding");
            } else if (setting("/proc/sys/net/ipv6/conf/all/forwarding") != "1") {
                // Older kernels cannot isolate IPv6 forwarding to two interfaces.
                enable("/proc/sys/net/ipv6/conf/" + name + "/force_forwarding"); enable("/proc/sys/net/ipv6/conf/" + output + "/force_forwarding");
            }
            rules << "add rule inet " << token << " forward iifname \"" << name << "\" oifname \"" << output << "\" "
                  << family << " saddr " << r.tunnel.str() << " " << family << " daddr " << r.prefix.str()
                  << " ct direction original ct state { new, established, related } accept\n";
            rules << "add rule inet " << token << " forward iifname \"" << output << "\" oifname \"" << name << "\" "
                  << family << " daddr " << r.tunnel.str() << " ct original " << family << " saddr " << r.tunnel.str()
                  << " ct original " << family << " daddr " << r.prefix.str() << " ct state { established, related } accept\n";
            if (r.snat) rules << "add rule inet " << token << " postrouting iifname \"" << name << "\" oifname \"" << output << "\" "
                << family << " saddr " << r.tunnel.str() << " " << family << " daddr " << r.prefix.str() << " masquerade\n";
        }
        rules << "add rule inet " << token << " forward iifname \"" << name << "\" drop\n"
              << "add rule inet " << token << " forward oifname \"" << name << "\" drop\n";
        command({"nft", "-f", "-"}, rules.str()); nat_owned = true;
#endif
        exports = next;
    }
    void clear() {
        std::string error;
        try { set_exports({}); } catch (const std::exception& e) { error = e.what(); }
        // A failed NAT removal must not prevent unrelated route/forwarding cleanup.
        try { restore_forwarding(); } catch (const std::exception& e) { if (error.empty()) error = e.what(); }
        for (std::size_t i = 0; i < routes.size();) {
            try { route(routes[i], false); routes.erase(routes.begin() + i); }
            catch (const std::exception& e) { if (error.empty()) error = e.what(); ++i; }
        }
        if (!error.empty()) throw std::runtime_error(error);
    }
};
SubnetPlatform::SubnetPlatform(const std::string& name, const Configure& c) : impl_(new Impl(name, c)) {}
SubnetPlatform::~SubnetPlatform() {
    try { impl_->clear(); }
    catch (const std::exception& e) { std::fprintf(stderr, "subnet cleanup failed: %s\n", e.what()); }
}
void SubnetPlatform::set_routes(const std::vector<ImportedRoute>& r) { impl_->set_routes(r); }
void SubnetPlatform::set_exports(const std::vector<AdvertisedRoute>& r) { impl_->set_exports(r); }
void SubnetPlatform::clear() { impl_->clear(); }
