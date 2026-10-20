#pragma once
#include "gossip.h"
#include "third_party/nlohmann/json.hpp"
#include <stdexcept>
namespace wire {
using Json = nlohmann::json;
constexpr std::size_t max_frame = 65536;
constexpr std::size_t max_data_frame = 65536;
std::string hex(const unsigned char* data, std::size_t size);
template<class T> std::string hex(const T& value) { return hex(value.data(), value.size()); }
Bytes unhex(const std::string& value, std::size_t maximum);
PublicKey key(const Json& value);
Json route(const PathAnnouncement& value);
PathAnnouncement route(const Json& value);
Bytes frame(const Json& message);
// Bit 31 of the network-order length marks binary data; control framing is
// unchanged. Only peers that negotiated TCP data may use these frames.
Bytes data_frame(const Bytes& packet);
class Decoder {
public:
    void append(const Bytes& bytes);
    bool next(Json& message);
    // A successful binary frame sets packet and clears message; a control
    // frame sets message and clears packet. Empty binary frames are invalid.
    bool next(Json& message, Bytes& packet);
private:
    bool next_frame(Json& message, Bytes* packet);
    Bytes bytes_;
    std::size_t offset_ = 0;
};
}
