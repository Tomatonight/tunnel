#include "tls.h"
#include <openssl/err.h>
#include <openssl/x509.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace {
void require_tls(bool ok, const char* what) {
    if (!ok) { ERR_clear_error(); throw std::runtime_error(std::string("TLS: ") + what); }
}
constexpr std::size_t tls_limit = 256 * 1024;
}
void TlsChannel::initialize(bool client) {
    client_ = client;
    ctx_ = SSL_CTX_new(TLS_method());
    require_tls(ctx_ != nullptr, "context allocation");
    require_tls(SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION) == 1 &&
                SSL_CTX_set_ciphersuites(ctx_, "TLS_AES_128_GCM_SHA256") == 1 &&
                SSL_CTX_set1_groups_list(ctx_, "X25519:P-256") == 1, "TLS 1.3 configuration");
    SSL_CTX_set_options(ctx_, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_num_tickets(ctx_, 0);
    SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_max_early_data(ctx_, 0);
}
TlsChannel::TlsChannel(bool client, const std::string& identity, PskLookup lookup)
    : psk_(true), identity_(identity), lookup_(std::move(lookup)) {
    try {
        initialize(client);
        SSL_CTX_set_psk_use_session_callback(ctx_, use_psk);
        SSL_CTX_set_psk_find_session_callback(ctx_, find_psk);
        ssl_ = SSL_new(ctx_); require_tls(ssl_ != nullptr, "SSL allocation");
        SSL_set_app_data(ssl_, this);
        auto* in = BIO_new(BIO_s_mem()); auto* out = BIO_new(BIO_s_mem());
        if (!in || !out) { BIO_free(in); BIO_free(out); throw std::runtime_error("TLS BIO allocation"); }
        SSL_set_bio(ssl_, in, out);
        if (client) SSL_set_connect_state(ssl_); else SSL_set_accept_state(ssl_);
    } catch (...) { SSL_free(ssl_); SSL_CTX_free(ctx_); throw; }
}
TlsChannel::TlsChannel(bool client, const IdentityKey& local, const PublicKey& remote) : remote_(remote) {
    try {
        initialize(client);
        std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
        require_tls(bool(cert) && X509_set_version(cert.get(), 2) == 1 &&
                    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1 &&
                    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) &&
                    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 315360000L) &&
                    X509_set_pubkey(cert.get(), local.native_key()) == 1, "identity certificate");
        auto* name = X509_get_subject_name(cert.get());
        require_tls(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    reinterpret_cast<const unsigned char*>("tunnel-process-identity"), -1, -1, 0) == 1 &&
                    X509_set_issuer_name(cert.get(), name) == 1 &&
                    X509_sign(cert.get(), local.native_key(), nullptr) > 0 &&
                    SSL_CTX_use_certificate(ctx_, cert.get()) == 1 &&
                    SSL_CTX_use_PrivateKey(ctx_, local.native_key()) == 1, "identity certificate signing");
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_certificate);
        SSL_CTX_set_verify_depth(ctx_, 0);
        ssl_ = SSL_new(ctx_); require_tls(ssl_ != nullptr, "SSL allocation");
        SSL_set_app_data(ssl_, this);
        auto* in = BIO_new(BIO_s_mem()); auto* out = BIO_new(BIO_s_mem());
        if (!in || !out) { BIO_free(in); BIO_free(out); throw std::runtime_error("TLS BIO allocation"); }
        SSL_set_bio(ssl_, in, out);
        if (client) SSL_set_connect_state(ssl_); else SSL_set_accept_state(ssl_);
    } catch (...) { SSL_free(ssl_); SSL_CTX_free(ctx_); throw; }
}
TlsChannel::~TlsChannel() { SSL_free(ssl_); SSL_CTX_free(ctx_); }
SSL_SESSION* TlsChannel::psk_session(SSL* ssl, const std::string& psk) {
    if (psk.empty()) return nullptr;
    Secret key{}; unsigned length = 0;
    require_tls(EVP_Digest(psk.data(), psk.size(), key.data(), &length, EVP_sha256(), nullptr) == 1,
                "PSK digest");
    const unsigned char cipher_id[] = {0x13, 0x01};
    auto* cipher = SSL_CIPHER_find(ssl, cipher_id);
    auto* session = SSL_SESSION_new();
    const bool ok = session && cipher && SSL_SESSION_set1_master_key(session, key.data(), key.size()) == 1 &&
        SSL_SESSION_set_cipher(session, cipher) == 1 && SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) == 1;
    OPENSSL_cleanse(key.data(), key.size());
    if (!ok) { SSL_SESSION_free(session); return nullptr; }
    return session;
}
int TlsChannel::use_psk(SSL* ssl, const EVP_MD* md, const unsigned char** id, std::size_t* len, SSL_SESSION** session) {
    try {
        auto& self = *static_cast<TlsChannel*>(SSL_get_app_data(ssl));
        if (md && EVP_MD_get_type(md) != NID_sha256) return 0;
        *id = reinterpret_cast<const unsigned char*>(self.identity_.data()); *len = self.identity_.size();
        *session = self.psk_session(ssl, self.lookup_(self.identity_));
        return *session != nullptr;
    } catch (...) { return 0; }
}
int TlsChannel::find_psk(SSL* ssl, const unsigned char* id, std::size_t len, SSL_SESSION** session) {
    try {
        if (!len || len > 256) return 0;
        auto& self = *static_cast<TlsChannel*>(SSL_get_app_data(ssl));
        self.identity_.assign(reinterpret_cast<const char*>(id), len);
        *session = self.psk_session(ssl, self.lookup_(self.identity_));
        return *session != nullptr;
    } catch (...) { return 0; }
}
int TlsChannel::verify_certificate(int, X509_STORE_CTX* store) {
    auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
    auto* self = static_cast<TlsChannel*>(SSL_get_app_data(ssl));
    if (!self || X509_STORE_CTX_get_error_depth(store) != 0) return 0;
    auto* cert = X509_STORE_CTX_get_current_cert(store);
    auto* key = X509_get0_pubkey(cert);
    PublicKey raw{}; std::size_t size = raw.size();
    // Trust is the exact Ed25519 key from authenticated routing, not a CA chain.
    return key && EVP_PKEY_is_a(key, "ED25519") &&
        EVP_PKEY_get_raw_public_key(key, raw.data(), &size) == 1 && size == raw.size() &&
        CRYPTO_memcmp(raw.data(), self->remote_.data(), raw.size()) == 0;
}
void TlsChannel::check(int result) {
    if (result > 0) return;
    const auto error = SSL_get_error(ssl_, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        require_tls(false, error == SSL_ERROR_ZERO_RETURN ? "peer closed" : "authentication or record failure");
}
bool TlsChannel::ready() const { return SSL_is_init_finished(ssl_) != 0; }
void TlsChannel::feed(const Bytes& bytes) {
    if (bytes.size() + BIO_ctrl_pending(SSL_get_rbio(ssl_)) > tls_limit) throw std::length_error("TLS receive limit");
    if (!bytes.empty()) require_tls(BIO_write(SSL_get_rbio(ssl_), bytes.data(), static_cast<int>(bytes.size())) ==
                                   static_cast<int>(bytes.size()), "BIO input");
    advance();
}
void TlsChannel::advance() {
    if (!ready()) { ERR_clear_error(); check(SSL_do_handshake(ssl_)); }
    if (ready() && psk_) require_tls(SSL_session_reused(ssl_) == 1, "external PSK was not used");
}
Bytes TlsChannel::drain() {
    const auto size = BIO_ctrl_pending(SSL_get_wbio(ssl_));
    if (size > tls_limit) throw std::length_error("TLS send limit");
    Bytes out(size);
    if (size) require_tls(BIO_read(SSL_get_wbio(ssl_), out.data(), static_cast<int>(size)) == static_cast<int>(size), "BIO output");
    return out;
}
Bytes TlsChannel::read() {
    Bytes out; unsigned char buffer[16384];
    if (!ready()) return out;
    for (unsigned i = 0; i < 16; ++i) {
        ERR_clear_error(); const auto n = SSL_read(ssl_, buffer, sizeof(buffer));
        if (n <= 0) { check(n); break; }
        out.insert(out.end(), buffer, buffer + n);
    }
    return out;
}
void TlsChannel::write(const Bytes& bytes) {
    require_tls(ready() && bytes.size() <= tls_limit && BIO_ctrl_pending(SSL_get_wbio(ssl_)) < tls_limit, "write state/limit");
    if (bytes.empty()) return;
    ERR_clear_error(); const int n = SSL_write(ssl_, bytes.data(), static_cast<int>(bytes.size()));
    check(n); require_tls(n == static_cast<int>(bytes.size()), "partial TLS write");
}
std::unique_ptr<CryptoSession> TlsChannel::session(CryptoScope scope, const std::string& context) const {
    require_tls(ready(), "export before handshake");
    const auto label = std::string("EXPORTER-tunnel-v1-") + std::to_string(static_cast<unsigned>(scope));
    std::array<unsigned char, 48> exported{};
    require_tls(SSL_export_keying_material(ssl_, exported.data(), exported.size(), label.data(), label.size(),
                reinterpret_cast<const unsigned char*>(context.data()), context.size(), 1) == 1, "key export");
    Secret secret{}; SessionId id{};
    std::copy_n(exported.begin(), secret.size(), secret.begin());
    std::copy_n(exported.begin() + secret.size(), id.size(), id.begin());
    // The exporter binds the full context. Hash it for HKDF's bounded info field;
    // a peer may authorize 64 IPv6 networks, exceeding the HKDF backend limit.
    Secret context_hash{}; unsigned hash_size = 0;
    require_tls(EVP_Digest(context.data(), context.size(), context_hash.data(), &hash_size, EVP_sha256(), nullptr) == 1,
                "context digest");
    auto keys = derive_keys(secret, id, scope,
        std::string(reinterpret_cast<const char*>(context_hash.data()), context_hash.size()), client_);
    OPENSSL_cleanse(secret.data(), secret.size()); OPENSSL_cleanse(exported.data(), exported.size());
    return std::unique_ptr<CryptoSession>(new CryptoSession(id, keys, scope));
}
