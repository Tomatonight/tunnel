#include "crypto.h"
#include "protocol.h"
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace {
void require(bool okay, const char* operation) {
    if (!okay) throw std::runtime_error(std::string("OpenSSL: ") + operation);
}
void put64(unsigned char* out, std::uint64_t n) {
    for (int i = 7; i >= 0; --i) { out[i] = static_cast<unsigned char>(n); n >>= 8; }
}
std::uint64_t get64(const unsigned char* in) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) result = (result << 8) | in[i];
    return result;
}
Secret hkdf(const Secret& secret, const SessionId& salt, const std::string& info) {
    if (info.size() > 1024) throw std::invalid_argument("key derivation context too long");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    require(bool(ctx), "HKDF context allocation");
    require(EVP_PKEY_derive_init(ctx.get()) == 1 && EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), secret.data(), static_cast<int>(secret.size())) == 1 &&
            EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), reinterpret_cast<const unsigned char*>(info.data()), static_cast<int>(info.size())) == 1,
            "HKDF initialization");
    Secret out{}; std::size_t size = out.size();
    require(EVP_PKEY_derive(ctx.get(), out.data(), &size) == 1 && size == out.size(), "HKDF derive");
    return out;
}
constexpr std::uint64_t rekey_sequence = std::uint64_t(1) << 32;
}
IdentityKey::IdentityKey() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    require(bool(ctx) && EVP_PKEY_keygen_init(ctx.get()) == 1 && EVP_PKEY_keygen(ctx.get(), &key_) == 1, "Ed25519 key generation");
}
IdentityKey::~IdentityKey() { EVP_PKEY_free(key_); }
PublicKey IdentityKey::public_key() const {
    PublicKey key{}; std::size_t size = key.size();
    require(EVP_PKEY_get_raw_public_key(key_, key.data(), &size) == 1 && size == key.size(), "public key export"); return key;
}
Bytes IdentityKey::sign(const Bytes& message) const {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(bool(ctx) && EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key_) == 1, "signature initialization");
    Bytes signature(64); std::size_t length = signature.size();
    require(EVP_DigestSign(ctx.get(), signature.data(), &length, message.data(), message.size()) == 1, "signature");
    signature.resize(length); return signature;
}
bool IdentityKey::verify(const PublicKey& key, const Bytes& message, const Bytes& signature) {
    if (signature.size() != 64) return false;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.data(), key.size()), EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(bool(pkey) && bool(ctx) && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) == 1, "verification initialization");
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}
DirectionalKeys::~DirectionalKeys() {
    OPENSSL_cleanse(send.data(), send.size()); OPENSSL_cleanse(receive.data(), receive.size());
}
DirectionalKeys derive_keys(const Secret& secret, const SessionId& session, CryptoScope scope, const std::string& context, bool initiator) {
    const auto prefix = std::string("tunnel/v1/") + std::to_string(static_cast<unsigned>(scope));
    DirectionalKeys result;
    result.send = hkdf(secret, session, prefix + (initiator ? "/i2r/" : "/r2i/") + context);
    result.receive = hkdf(secret, session, prefix + (initiator ? "/r2i/" : "/i2r/") + context);
    return result;
}
SessionId random_session_id() {
    SessionId id{}; require(RAND_bytes(id.data(), static_cast<int>(id.size())) == 1, "session random bytes"); return id;
}
CryptoSession::CryptoSession(const SessionId& id, const DirectionalKeys& keys, CryptoScope scope)
    : id_(id), keys_(keys), scope_(scope) {
    if (keys.send == keys.receive) throw std::invalid_argument("directional traffic keys must differ");
    send_ = EVP_CIPHER_CTX_new(); receive_ = EVP_CIPHER_CTX_new();
    if (!send_ || !receive_) { EVP_CIPHER_CTX_free(send_); EVP_CIPHER_CTX_free(receive_); throw std::runtime_error("cipher context allocation failed"); }
}
CryptoSession::~CryptoSession() { EVP_CIPHER_CTX_free(send_); EVP_CIPHER_CTX_free(receive_); }
Bytes CryptoSession::seal(const Bytes& plain, const Bytes& aad) {
    if (plain.size() > 65535 || aad.size() > 4096) throw std::length_error("AEAD input too large");
    if (next_sequence_ >= rekey_sequence) throw std::runtime_error("session requires rekey before further transmission");
    const auto sequence = next_sequence_++;
    Bytes out(protocol::record_header_size + plain.size() + protocol::authentication_tag_size);
    std::memcpy(out.data(), "TNL1", 4); out[4] = 1; out[5] = static_cast<unsigned char>(scope_);
    out[6] = static_cast<unsigned char>(plain.size() >> 8); out[7] = static_cast<unsigned char>(plain.size());
    std::copy(id_.begin(), id_.end(), out.begin() + 8); put64(out.data() + 24, sequence);
    unsigned char nonce[12]{}; put64(nonce + 4, sequence);
    int length = 0, final_length = 0;
    require(EVP_EncryptInit_ex(send_, EVP_aes_256_gcm(), nullptr, keys_.send.data(), nonce) == 1 &&
            EVP_EncryptUpdate(send_, nullptr, &length, out.data(), protocol::record_header_size) == 1, "encrypt initialization");
    if (!aad.empty()) require(EVP_EncryptUpdate(send_, nullptr, &length, aad.data(), static_cast<int>(aad.size())) == 1, "encrypt additional data");
    require(EVP_EncryptUpdate(send_, out.data() + protocol::record_header_size, &length, plain.data(), static_cast<int>(plain.size())) == 1 &&
            EVP_EncryptFinal_ex(send_, out.data() + protocol::record_header_size + length, &final_length) == 1 &&
            EVP_CIPHER_CTX_ctrl(send_, EVP_CTRL_GCM_GET_TAG, protocol::authentication_tag_size, out.data() + protocol::record_header_size + plain.size()) == 1,
            "AEAD encryption");
    return out;
}
bool CryptoSession::peek_session_id(const Bytes& packet, SessionId* id) {
    if (!id || packet.size() < protocol::record_overhead || std::memcmp(packet.data(), "TNL1", 4) || packet[4] != 1) return false;
    std::copy_n(packet.begin() + 8, id->size(), id->begin()); return true;
}
bool CryptoSession::open(const Bytes& packet, Bytes& plain, const Bytes& aad) {
    if (&packet == &plain || &aad == &plain) throw std::invalid_argument("decryption output must not alias input");
    plain.clear();
    SessionId id;
    if (!peek_session_id(packet, &id) || id != id_ || packet[5] != static_cast<unsigned char>(scope_) || aad.size() > 4096) return false;
    const std::size_t size = (unsigned(packet[6]) << 8) | packet[7];
    if (packet.size() != size + protocol::record_overhead) return false;
    const auto sequence = get64(packet.data() + 24);
    if (!sequence || sequence >= rekey_sequence) return false;
    if (sequence <= receive_highest_) {
        const auto delta = receive_highest_ - sequence;
        if (delta >= 64 || (receive_window_ & (std::uint64_t(1) << delta))) return false;
    }
    unsigned char nonce[12]{}; put64(nonce + 4, sequence);
    Bytes decoded(size + 16); int length = 0, final_length = 0;
    require(EVP_DecryptInit_ex(receive_, EVP_aes_256_gcm(), nullptr, keys_.receive.data(), nonce) == 1 &&
            EVP_DecryptUpdate(receive_, nullptr, &length, packet.data(), protocol::record_header_size) == 1, "decrypt initialization");
    if (!aad.empty()) require(EVP_DecryptUpdate(receive_, nullptr, &length, aad.data(), static_cast<int>(aad.size())) == 1, "decrypt additional data");
    require(EVP_DecryptUpdate(receive_, decoded.data(), &length, packet.data() + protocol::record_header_size, static_cast<int>(size)) == 1 &&
            EVP_CIPHER_CTX_ctrl(receive_, EVP_CTRL_GCM_SET_TAG, protocol::authentication_tag_size,
                const_cast<unsigned char*>(packet.data() + protocol::record_header_size + size)) == 1, "AEAD decryption");
    if (EVP_DecryptFinal_ex(receive_, decoded.data() + length, &final_length) != 1) {
        OPENSSL_cleanse(decoded.data(), decoded.size()); return false;
    }
    // Authentication precedes replay-window advancement, including large jumps.
    if (sequence > receive_highest_) {
        const auto delta = sequence - receive_highest_;
        receive_window_ = delta >= 64 ? 1 : (receive_window_ << delta) | 1;
        receive_highest_ = sequence;
    } else receive_window_ |= std::uint64_t(1) << (receive_highest_ - sequence);
    decoded.resize(size); plain = std::move(decoded); return true;
}
