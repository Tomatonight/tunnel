#pragma once
#include <openssl/evp.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;
using PublicKey = std::array<unsigned char, 32>;
using SessionId = std::array<unsigned char, 16>;
using Secret = std::array<unsigned char, 32>;

class IdentityKey {
public:
    IdentityKey();
    ~IdentityKey();
    IdentityKey(const IdentityKey&) = delete;
    IdentityKey& operator=(const IdentityKey&) = delete;
    PublicKey public_key() const;
    Bytes sign(const Bytes& message) const;
    static bool verify(const PublicKey& key, const Bytes& message, const Bytes& signature);
    EVP_PKEY* native_key() const { return key_; } // Borrowed; owned by this process identity.
private:
    EVP_PKEY* key_ = nullptr;
};

enum class CryptoScope : unsigned char { Link = 1, EndToEnd = 2 };
struct DirectionalKeys {
    Secret send{};
    Secret receive{};
    ~DirectionalKeys();
};
// secret MUST come from an authenticated handshake, not directly from a PSK.
// session must be fresh for every handshake; context binds identities/network.
DirectionalKeys derive_keys(const Secret& secret, const SessionId& session,
                            CryptoScope scope, const std::string& context, bool initiator);
SessionId random_session_id();

class CryptoSession {
public:
    CryptoSession(const SessionId& id, const DirectionalKeys& keys, CryptoScope scope);
    ~CryptoSession();
    CryptoSession(const CryptoSession&) = delete;
    CryptoSession& operator=(const CryptoSession&) = delete;
    Bytes seal(const Bytes& plaintext, const Bytes& additional_aad = {});
    bool open(const Bytes& packet, Bytes& plaintext, const Bytes& additional_aad = {});
    const SessionId& id() const { return id_; }
    // Only the selected kernel backend may consume these keys. It owns all
    // sequence numbers and replay windows; never mix seal/open with offload.
    const DirectionalKeys& offload_keys() const { return keys_; }
    static bool peek_session_id(const Bytes& packet, SessionId* id);
private:
    SessionId id_;
    DirectionalKeys keys_;
    CryptoScope scope_;
    EVP_CIPHER_CTX* send_ = nullptr;
    EVP_CIPHER_CTX* receive_ = nullptr;
    std::uint64_t next_sequence_ = 1;
    std::uint64_t receive_highest_ = 0;
    std::uint64_t receive_window_ = 0;
};
