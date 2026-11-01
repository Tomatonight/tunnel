#include "node.h"
#include "protocol.h"
#include <algorithm>
#include <cstdio>
#include <csignal>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <openssl/rand.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
namespace {
volatile std::sig_atomic_t stopping = 0;
volatile std::sig_atomic_t reload_requested = 0;
void signal_stop(int) { stopping = 1; }
void signal_reload(int) { reload_requested = 1; }
// A desktop controller owns this input pipe. Read a bounded amount on the same
// event-loop thread; neither an idle parent nor a partial command may block it.
class StdioControl {
public:
    explicit StdioControl(bool enabled) : enabled_(enabled) {
        if (!enabled_) return;
#ifdef _WIN32
        input_ = GetStdHandle(STD_INPUT_HANDLE);
        if (!input_ || input_ == INVALID_HANDLE_VALUE || GetFileType(input_) != FILE_TYPE_PIPE)
            throw std::invalid_argument("--stdio-control requires a stdin pipe");
#else
        struct stat info;
        if (fstat(STDIN_FILENO, &info) || !S_ISFIFO(info.st_mode))
            throw std::invalid_argument("--stdio-control requires a stdin pipe");
        old_flags_ = fcntl(STDIN_FILENO, F_GETFL);
        if (old_flags_ < 0 || fcntl(STDIN_FILENO, F_SETFL, old_flags_ | O_NONBLOCK) < 0)
            throw std::runtime_error("cannot make control stdin nonblocking");
#endif
    }
    ~StdioControl() {
#ifndef _WIN32
        if (enabled_ && old_flags_ >= 0) fcntl(STDIN_FILENO, F_SETFL, old_flags_);
#endif
    }
    bool poll(const std::function<wire::Json(const std::string&)>& request) {
        if (!enabled_) return false;
        unsigned invalid = 0;
        bool stop = false;
        // Limit both parsing work and error output when a parent sends junk.
        std::size_t budget = 4096;
        while (budget && !stop) {
            char bytes[512];
            std::size_t count = 0;
#ifdef _WIN32
            DWORD available = 0, received = 0;
            if (!PeekNamedPipe(input_, nullptr, 0, nullptr, &available, nullptr)) {
                const DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)
                    std::cerr << "control: parent input closed; stopping\n";
                else std::cerr << "control: cannot inspect stdin pipe; stopping\n";
                stop = true; break;
            }
            if (!available) break;
            const DWORD wanted = static_cast<DWORD>((std::min)(budget, (std::min)(sizeof(bytes), static_cast<std::size_t>(available))));
            if (!ReadFile(input_, bytes, wanted, &received, nullptr) || !received) {
                std::cerr << "control: parent input closed or failed; stopping\n";
                stop = true; break;
            }
            count = received;
#else
            const auto received = read(STDIN_FILENO, bytes, (std::min)(budget, sizeof(bytes)));
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) break; // Retry next timer tick, never spin.
                std::cerr << "control: cannot read stdin pipe; stopping\n";
                stop = true; break;
            }
            if (!received) {
                std::cerr << "control: parent input closed; stopping\n";
                stop = true; break;
            }
            count = static_cast<std::size_t>(received);
#endif
            budget -= count;
            for (std::size_t i = 0; i < count && !stop; ++i) {
                const auto ch = static_cast<unsigned char>(bytes[i]);
                if (ch == '\n') {
                    if (discard_rpc_) {
                        const wire::Json response{{"id", nullptr}, {"ok", false}, {"error", discard_reason_}};
                        std::cout << "TUNNEL_RPC " << response.dump() << '\n' << std::flush;
                    } else if (!discard_) {
                        if (!line_.empty() && line_.back() == '\r') line_.pop_back();
                        if (line_ == "STOP" || line_ == "stop") {
                            std::cerr << "control: stop requested\n";
                            stop = true;
                        } else if (looks_like_rpc()) {
                            // Applying a configuration may log to stderr. Finish
                            // it before emitting any prefix: the host merges both
                            // streams and must receive an intact RPC response.
                            const auto reply = request(line_);
                            std::cout << "TUNNEL_RPC " << reply.dump(-1, ' ', true) << '\n' << std::flush;
                        } else ++invalid;
                    }
                    line_.clear(); discard_ = false; discard_rpc_ = false;
                } else if (!discard_) {
                    if (ch == 0 || line_.size() == 16384) {
                        discard_rpc_ = looks_like_rpc();
                        discard_reason_ = ch == 0 ? "invalid_request" : "request_too_large";
                        line_.clear(); discard_ = true; ++invalid;
                    } else line_.push_back(static_cast<char>(ch));
                }
            }
        }
        if (invalid) std::cerr << "control: ignored " << invalid << " invalid command(s); expected STOP or bounded JSON RPC\n";
        return stop;
    }
private:
    bool looks_like_rpc() const {
        const auto start = line_.find_first_not_of(" \t\r");
        return start != std::string::npos && line_[start] == '{';
    }
    bool enabled_, discard_ = false, discard_rpc_ = false;
    std::string line_, discard_reason_;
#ifdef _WIN32
    HANDLE input_ = INVALID_HANDLE_VALUE;
#else
    int old_flags_ = -1;
#endif
};
unsigned number(const std::string& value, unsigned maximum) {
    std::size_t end = 0; const auto result = std::stoul(value, &end);
    if (end != value.size() || result > maximum) throw std::invalid_argument("invalid numeric option");
    return static_cast<unsigned>(result);
}
void status_file(const std::string& path, const wire::Json& status) {
    if (path.empty()) return;
    const auto temp = path + ".tmp";
    { std::ofstream file(temp.c_str(), std::ios::binary | std::ios::trunc);
      if (!file || !(file << status.dump(2) << '\n')) throw std::runtime_error("cannot write status file"); }
#ifdef _WIN32
    if (!MoveFileExA(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("cannot replace status file");
#else
    if (std::rename(temp.c_str(), path.c_str())) throw std::runtime_error("cannot replace status file");
#endif
}
void resolve_service_state(Configure& config, const std::string& configuration_path) {
    if (!config.address_server.enabled) return;
    const auto& path = config.address_server.state_file;
    bool absolute = !path.empty() && path[0] == '/';
#ifdef _WIN32
    absolute = absolute || (!path.empty() && path[0] == '\\') || (path.size() > 1 && path[1] == ':');
#endif
    if (absolute) return;
    const auto split = configuration_path.find_last_of("/\\");
    if (split != std::string::npos) config.address_server.state_file = configuration_path.substr(0, split + 1) + path;
}
std::string configuration_text(const std::string& path) {
    std::ifstream input(path.c_str(), std::ios::binary);
    if (!input) throw std::runtime_error("cannot open configuration file");
    std::string text; char buffer[4096];
    while (input) {
        input.read(buffer, sizeof(buffer)); text.append(buffer, static_cast<std::size_t>(input.gcount()));
        if (text.size() > 1048576) throw std::runtime_error("configuration exceeds 1 MiB");
    }
    if (!input.eof()) throw std::runtime_error("cannot read configuration file");
    return text;
}
wire::Json apply_configuration(Node& node, const std::string& text, const std::string& path,
                               const std::string& backend_override) {
    auto config = parse_config(text);
    if (!backend_override.empty()) config.device_backend = backend_override;
    resolve_service_state(config, path);
    return node.apply_config(config);
}
// Configuration is passed by private file, keeping the bounded parent pipe free
// of megabyte-sized requests and preserving the existing signing RPC limits.
wire::Json control_request(Node& node, const std::string& text, const std::string& backend_override) {
    using Json = wire::Json;
    Json id = nullptr;
    try {
        std::vector<std::set<std::string>> keys;
        const auto request = Json::parse(text, [&](int depth, Json::parse_event_t event, Json& value) {
            if (depth > 4) throw std::invalid_argument("invalid_request");
            if (event == Json::parse_event_t::object_start) keys.emplace_back();
            else if (event == Json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second)
                throw std::invalid_argument("invalid_request");
            else if (event == Json::parse_event_t::object_end) keys.pop_back();
            return true;
        });
        if (!request.is_object() || !request.contains("method") || !request["method"].is_string())
            return node.remote_control(text);
        const auto method = request["method"].get<std::string>();
        if (method != "config_apply" && method != "config_get") return node.remote_control(text);
        if (!request.contains("id") || !(request["id"].is_number_integer() || request["id"].is_string()))
            throw std::invalid_argument("invalid_request");
        if (request["id"].is_string() && request["id"].get<std::string>().size() > 128)
            throw std::invalid_argument("invalid_request");
        id = request["id"];
        for (auto it = request.begin(); it != request.end(); ++it)
            if (it.key() != "id" && it.key() != "method" && !(method == "config_apply" && it.key() == "path"))
                throw std::invalid_argument("invalid_request");
        Json result;
        if (method == "config_get") result = Json::parse(serialize_config(node.configuration()));
        else {
            if (!request.contains("path") || !request["path"].is_string()) throw std::invalid_argument("invalid_request");
            const auto path = request["path"].get<std::string>();
            if (path.empty() || path.size() > 4096 || path.find('\0') != std::string::npos)
                throw std::invalid_argument("invalid_request");
            result = apply_configuration(node, configuration_text(path), path, backend_override);
        }
        return {{"id", id}, {"ok", true}, {"result", result}};
    } catch (const Json::exception&) {
        return {{"id", id}, {"ok", false}, {"error", "invalid_request"}};
    } catch (const std::exception& error) {
        // Config parsers and apply_config return bounded diagnostics, never JSON/PSKs.
        return {{"id", id}, {"ok", false}, {"error", std::string(error.what()).substr(0, 500)}};
    }
}
}
int main(int argc, char** argv) {
    try {
        bool check = false, normalize = false, generate_key = false, path_given = false, stdio_control = false, watch_config = false;
        std::string path = "config/default.json", name, status, export_client, backend_override;
        int tun_fd = -1; unsigned run_for = 0;
        for (int i = 1; i < argc; ++i) {
            const std::string arg(argv[i]);
            if (arg == "--help") {
                std::puts("Usage: tunnel [config/default.json] [--check | --normalize-config] [--tun-name NAME]\n"
                          "              [--tun-fd FD] [--status-file PATH] [--run-for SECONDS]\n"
                          "              [--stdio-control] [--watch-config] [--device-backend tun|kernel]\n"
                          "              [--export-client NODE_ADDRESS]\n"
                          "       tunnel --generate-key\n"
                          "Run a single-threaded encrypted IP overlay. --check needs no device privileges.\n"
                          "Linux: CAP_NET_ADMIN/root and iproute2. Windows: administrator and wintun.dll.\n"
                          "--device-backend: kernel (Linux default) or tun (default on other platforms, including Android).\n"
                          "Overrides JSON for this process, including reloads; kernel tries to load the matching tunnel_kmod module\n"
                          "from build/kernel/tunnel_kmod.ko (or TUNNEL_KERNEL_MODULE) and unloads modules it loaded on exit.\n"
                          "Inherited TUN fds require backend tun and must already be configured; ownership transfers to the process.\n"
                          "--stdio-control: parent stdin pipe accepts STOP/stop and remote desktop JSON RPC; EOF stops cleanly.\n"
                          "--watch-config: reload changed JSON every second; invalid changes keep the running configuration.\n"
                          "POSIX SIGHUP reloads JSON when running without --stdio-control.\n"
                          "--normalize-config: validate and print simplified JSON, including configured PSKs.\n"
                          "--generate-key: print a fresh 32-byte random PSK as hexadecimal.\n"
                          "--export-client: print a server-authorized client configuration (contains its PSK).\n"
                          "An address_server-only configuration runs without TUN/UDP or administrator privileges."); return 0;
            } else if (arg == "--check") check = true;
            else if (arg == "--normalize-config") normalize = true;
            else if (arg == "--generate-key") generate_key = true;
            else if (arg == "--stdio-control") stdio_control = true;
            else if (arg == "--watch-config") watch_config = true;
            else if (arg == "--tun-name" || arg == "--status-file" || arg == "--tun-fd" || arg == "--run-for" || arg == "--export-client" || arg == "--device-backend") {
                if (++i == argc) throw std::invalid_argument("option requires a value: " + arg);
                if (arg == "--tun-name") name = argv[i];
                else if (arg == "--status-file") status = argv[i];
                else if (arg == "--tun-fd") tun_fd = static_cast<int>(number(argv[i], std::numeric_limits<int>::max()));
                else if (arg == "--export-client") export_client = argv[i];
                else if (arg == "--device-backend") {
                    backend_override = argv[i];
                    if (backend_override != "tun" && backend_override != "kernel")
                        throw std::invalid_argument("--device-backend: expected tun or kernel");
                }
                else run_for = number(argv[i], 86400);
            } else if (!arg.empty() && arg[0] != '-' && !path_given) { path = arg; path_given = true; }
            else throw std::invalid_argument("unknown option or repeated configuration path: " + arg);
        }
        if (generate_key) {
            if (argc != 2) throw std::invalid_argument("--generate-key does not accept other arguments");
            unsigned char bytes[32];
            if (RAND_bytes(bytes, sizeof(bytes)) != 1) throw std::runtime_error("cannot generate shared key");
            for (const auto byte : bytes) std::printf("%02x", static_cast<unsigned>(byte));
            std::putchar('\n'); OPENSSL_cleanse(bytes, sizeof(bytes)); return 0;
        }
        if (check && normalize) throw std::invalid_argument("choose --check or --normalize-config");
        if (watch_config && stdio_control) throw std::invalid_argument("parent-managed cores use config_apply instead of --watch-config");
        SocketSystem sockets;
        const auto initial_text = configuration_text(path);
        g_config = parse_config(initial_text);
        if (!backend_override.empty()) g_config.device_backend = backend_override;
        if (!export_client.empty()) {
            if (check || normalize) throw std::invalid_argument("--export-client cannot be combined with check/normalize");
            const auto endpoint = Endpoint::parse(export_client);
            const auto& server = g_config.address_server;
            if (!server.enabled) throw std::invalid_argument("address server is not configured");
            AddressClientConfig selected;
            if (!server.shared_key.empty()) {
                selected.shared_key = server.shared_key; selected.networks = server.networks;
            } else {
                for (const auto& client : server.clients) if (client.address == endpoint) selected = client;
                if (selected.shared_key.empty()) throw std::invalid_argument("node is not authorized by this address server");
            }
            wire::Json networks = wire::Json::array();
            for (const auto& n : selected.networks) networks.push_back(n.str());
            wire::Json doc{{"address", endpoint.str()}, {"address_clients", wire::Json::array({
                {{"address", server.address.str()}, {"shared_key", selected.shared_key}, {"networks", networks}}
            })}};
            std::cout << serialize_config(parse_config(doc.dump())); return 0;
        }
        if (normalize) { std::cout << serialize_config(g_config); return 0; }
        if (check) {
            if (g_config.networks.empty()) {
                if (!g_config.address_server.shared_key.empty())
                    std::printf("Configuration valid: address server, %zu pools, shared-key admission; no TUN or UDP socket\n",
                        g_config.address_server.networks.size());
                else std::printf("Configuration valid: address server, %zu pools, %zu authorized nodes; no TUN or UDP socket\n",
                    g_config.address_server.networks.size(), g_config.address_server.clients.size());
                return 0;
            }
            const auto family = g_config.listen.address.ip.family;
            std::printf("Configuration valid: device backend %s, %zu peers, %zu networks\n"
                        "TUN MTU: %u; outer MTU budget: %u; maximum TUN MTU: %zu\n",
                g_config.device_backend.c_str(), g_config.peers.size(), g_config.networks.size(), g_config.tun_mtu, g_config.transport_mtu,
                protocol::maximum_tun_mtu(g_config.transport_mtu, family)); return 0;
        }
        std::signal(SIGINT, signal_stop); std::signal(SIGTERM, signal_stop);
#ifdef SIGHUP
        if (!stdio_control) std::signal(SIGHUP, signal_reload);
#endif
#ifdef SIGPIPE
        std::signal(SIGPIPE, SIG_IGN);
#endif
        StdioControl control(stdio_control);
        EventLoop loop;
        resolve_service_state(g_config, path);
        std::unique_ptr<PacketDevice> device;
        if (!g_config.networks.empty()) device = open_device(loop, g_config, name, tun_fd);
        else if (tun_fd >= 0) throw std::invalid_argument("address server does not use a TUN fd");
        NodeOptions options; options.log = [](const std::string& text) { std::cerr << text << '\n'; };
        if (tun_fd < 0) options.device_factory = [&loop, name](const Configure& config) {
            return config.networks.empty() ? std::unique_ptr<PacketDevice>() : open_device(loop, config, name);
        };
        Node node(loop, g_config, std::move(device), options); node.start();
        std::string observed_config = initial_text, last_reload_error;
        auto next_watch = std::chrono::steady_clock::now();
        bool status_failed = false;
        auto update_status = [&] {
            try { status_file(status, node.status()); status_failed = false; }
            catch (const std::exception& e) {
                // Monitoring files can be temporarily locked by readers on Windows.
                // Retry on the next tick without interrupting working peer sessions.
                if (!status_failed) std::cerr << "status: " << e.what() << " (will retry)\n";
                status_failed = true;
            }
        };
        auto monitor = loop.addTimer(std::chrono::milliseconds(250), [&](evutil_socket_t, short) {
            if (control.poll([&](const std::string& text) { return control_request(node, text, backend_override); })) stopping = 1;
            const auto now = std::chrono::steady_clock::now();
            if (!stopping && (reload_requested || (watch_config && now >= next_watch))) {
                const bool forced = reload_requested != 0; reload_requested = 0;
                next_watch = now + std::chrono::seconds(1);
                try {
                    const auto text = configuration_text(path);
                    if (forced || text != observed_config) {
                        observed_config = text;
                        const auto result = apply_configuration(node, text, path, backend_override);
                        if (!result.value("ok", false)) throw std::runtime_error(result.value("error", "configuration reload failed") +
                            (result.contains("rollback_error") ? "; rollback failed: " + result["rollback_error"].get<std::string>() : ""));
                        std::cerr << "configuration applied: " << result.value("mode", "unknown") << '\n';
                    }
                    last_reload_error.clear();
                } catch (const std::exception& error) {
                    if (last_reload_error != error.what()) std::cerr << "configuration reload failed: " << error.what() << '\n';
                    last_reload_error = error.what();
                }
            }
            if (stopping) { node.stop(); loop.breakLoop(); }
            update_status();
        }, true);
        EventLoop::Handle deadline;
        if (run_for) deadline = loop.addTimer(std::chrono::milliseconds(run_for * 1000), [&](evutil_socket_t, short) { stopping = 1; });
        update_status(); loop.run(); node.stop(); update_status(); return 0;
    } catch (const std::exception& e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
