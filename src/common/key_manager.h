/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_KEY_MANAGER_H
#define IMPENNETRABLES_KEY_MANAGER_H

#include <atomic>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "config.h"

namespace impenn {

class KeyManager {
public:
    static KeyManager &get();

    KeyManager(KeyManager const &) = delete;

    KeyManager(KeyManager &&) = delete;

    KeyManager &operator=(KeyManager const &) = delete;

    KeyManager &operator=(KeyManager &&) = delete;

    bool is_ready();

    int generate_auth_file(const char *file_name);

    int load_auth_file(const char *file_name);

    SSL_CTX *create_tls_context();

    int generate_card_file(const char *account, const char *file_name);

    int verify_card_file(const char *account, const char *file_name);

    int delete_card_file(const char *file_name);

    void dump_crypto();

protected:
    explicit KeyManager();

    ~KeyManager();

private:
    enum class Mode {
        unknown, bank, atm
    };

    std::atomic_bool ready;
    Mode mode;

    EVP_PKEY *ca_pkey;
    EC_KEY *ca_ecc_pkey;
    X509 *ca_cert;
    X509_NAME *ca_name;

    EVP_PKEY *bank_pkey;
    EC_KEY *bank_ecc_pkey;
    X509 *bank_cert;
    X509_NAME *bank_name;

    EVP_PKEY *atm_pkey;
    EC_KEY *atm_ecc_pkey;
    X509 *atm_cert;
    X509_NAME *atm_name;

    void add_name_entry(X509_NAME *name, const char *tag, const unsigned char *value);

    std::string get_key_pem(EVP_PKEY *key);

    std::string get_cert_pem(X509 *cert);
    
    void print_error(const char *message, const char *error);
};

}

#endif //IMPENNETRABLES_KEY_MANAGER_H
