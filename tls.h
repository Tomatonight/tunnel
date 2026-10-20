#pragma once
#include "crypto.h"
#include <openssl/ssl.h>
#include <functional>
#include <memory>

// TLS 1.3 over memory BIOs. Transport framing is supplied by TCP or routed
// control messages. No early data, tickets, renegotiation or plaintext fallback.
class TlsChannel {
public:
    using PskLookup = std::function<std::string(const std::string&)>;
    TlsChannel(bool client, const std::string& identity, PskLookup lookup);
    TlsChannel(bool client, const IdentityKey& local, const PublicKey& remote);
    ~TlsChannel();
    TlsChannel(const TlsChannel&) = delete;
    TlsChannel& operator=(const TlsChannel&) = delete;
    void feed(const Bytes& bytes);
    void advance();
    Bytes drain();
    Bytes read();
    void write(const Bytes& bytes);
    bool ready() const;
    std::unique_ptr<CryptoSession> session(CryptoScope scope, const std::string& context) const;
    const std::string& psk_identity() const { return identity_; }
private:
    void initialize(bool client);
    void check(int result);
    SSL_SESSION* psk_session(SSL* ssl, const std::string& psk);
    static int use_psk(SSL*, const EVP_MD*, const unsigned char**, std::size_t*, SSL_SESSION**);
    static int find_psk(SSL*, const unsigned char*, std::size_t, SSL_SESSION**);
    static int verify_certificate(int, X509_STORE_CTX*);
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    bool client_ = false, psk_ = false;
    std::string identity_;
    PskLookup lookup_;
    PublicKey remote_{};
};
