/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#include "key_manager.h"

#include <iostream>
#include <fstream>
#include <memory>
#include <unistd.h>

#include <json/json.hpp>

using namespace impenn;
using json = nlohmann::json;

KeyManager &impenn::KeyManager::get() {
    static KeyManager instance;
    return instance;
}

impenn::KeyManager::KeyManager()
        : ready(false), mode(Mode::unknown) {
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    OpenSSL_add_ssl_algorithms();
    SSL_library_init();
}

impenn::KeyManager::~KeyManager() {
    try {
        if (atm_cert != nullptr) X509_free(atm_cert);
        if (atm_pkey != nullptr) EVP_PKEY_free(atm_pkey);

        if (bank_cert != nullptr) X509_free(bank_cert);
        if (bank_pkey != nullptr) EVP_PKEY_free(bank_pkey);

        if (ca_cert != nullptr) X509_free(ca_cert);
        if (ca_pkey != nullptr) EVP_PKEY_free(ca_pkey);

        ERR_free_strings();
    } catch (const std::exception &e) {
        print_error("destructor error", e.what());
    }
}

bool impenn::KeyManager::is_ready() {
    return ready && mode != Mode::unknown;
}

int impenn::KeyManager::generate_auth_file(const char *file_name) {
    if (mode == Mode::atm) return config::ERROR_INVALID_STATE;
    if (!config::OVERWRITE_AUTH_FILE && access(file_name, F_OK) != -1) {
        print_error("invalid auth file", "file exists");
        return config::ERROR_BANK_AUTH_FILE_EXIST;
    }

    ca_pkey = EVP_PKEY_new();
    if (ca_pkey == nullptr) {
        print_error("failed to allocate CA EVP_PKEY", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }
    ca_ecc_pkey = EC_KEY_new_by_curve_name(config::ELLIPTIC_CURVE);
    EC_KEY_set_asn1_flag(ca_ecc_pkey, OPENSSL_EC_NAMED_CURVE);
    EVP_PKEY_assign_EC_KEY(ca_pkey, ca_ecc_pkey);
    if (EC_KEY_generate_key(ca_ecc_pkey) < 0) {
        print_error("failed to generate CA private key", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    ca_cert = X509_new();
    X509_set_version(ca_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(ca_cert), config::CERT_DURATION);
    X509_set_pubkey(ca_cert, ca_pkey);
    ca_name = X509_get_subject_name(ca_cert);
    add_name_entry(ca_name, "C", config::NAME_C);
    add_name_entry(ca_name, "O", config::NAME_O);
    add_name_entry(ca_name, "CN", (unsigned char *) "Root CA");
    X509_set_issuer_name(ca_cert, ca_name);

    if (X509_sign(ca_cert, ca_pkey, EVP_sha256()) < 0) {
        print_error("failed to sign CA certificate", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    bank_pkey = EVP_PKEY_new();
    if (bank_pkey == nullptr) {
        print_error("failed to allocate Bank EVP_PKEY", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }
    bank_ecc_pkey = EC_KEY_new_by_curve_name(config::ELLIPTIC_CURVE);
    EC_KEY_set_asn1_flag(bank_ecc_pkey, OPENSSL_EC_NAMED_CURVE);
    EVP_PKEY_assign_EC_KEY(bank_pkey, bank_ecc_pkey);
    if (EC_KEY_generate_key(bank_ecc_pkey) < 0) {
        print_error("failed to generate bank private key", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    bank_cert = X509_new();
    X509_set_version(bank_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(bank_cert), 2);
    X509_gmtime_adj(X509_get_notBefore(bank_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(bank_cert), config::CERT_DURATION);
    X509_set_pubkey(bank_cert, bank_pkey);
    bank_name = X509_get_subject_name(bank_cert);
    add_name_entry(bank_name, "C", config::NAME_C);
    add_name_entry(bank_name, "O", config::NAME_O);
    add_name_entry(bank_name, "CN", (unsigned char *) "Bank");
    X509_set_issuer_name(bank_cert, ca_name);

    if (X509_sign(bank_cert, ca_pkey, EVP_sha256()) < 0) {
        print_error("failed to sign bank certificate", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    atm_pkey = EVP_PKEY_new();
    if (atm_pkey == nullptr) {
        print_error("failed to allocate Bank EVP_PKEY", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }
    atm_ecc_pkey = EC_KEY_new_by_curve_name(config::ELLIPTIC_CURVE);
    EC_KEY_set_asn1_flag(atm_ecc_pkey, OPENSSL_EC_NAMED_CURVE);
    EVP_PKEY_assign_EC_KEY(atm_pkey, atm_ecc_pkey);
    if (EC_KEY_generate_key(atm_ecc_pkey) < 0) {
        print_error("failed to generate bank private key", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    atm_cert = X509_new();
    X509_set_version(atm_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(atm_cert), 3);
    X509_gmtime_adj(X509_get_notBefore(atm_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(atm_cert), config::CERT_DURATION);
    X509_set_pubkey(atm_cert, atm_pkey);
    atm_name = X509_get_subject_name(atm_cert);
    add_name_entry(atm_name, "C", config::NAME_C);
    add_name_entry(atm_name, "O", config::NAME_O);
    add_name_entry(atm_name, "CN", (unsigned char *) "ATM");
    X509_set_issuer_name(atm_cert, ca_name);

    if (X509_sign(atm_cert, ca_pkey, EVP_sha256()) < 0) {
        print_error("failed to sign bank certificate", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }


    try {
        json auth;
        auth["atm_key"] = get_key_pem(atm_pkey);
        auth["atm_cert"] = get_cert_pem(atm_cert);
        auth["ca_cert"] = get_cert_pem(ca_cert);

        std::ofstream auth_file(file_name);
        auth_file << auth.dump();
        auth_file.flush();
        auth_file.close();
        std::cout << config::CREATED_STR << std::endl;
    } catch (const std::exception &e) {

        print_error("failed to save auth file", e.what());
        return config::ERROR_UNKNOWN;
    }

    mode = Mode::bank;
    ready = true;
    return 0;
}

int impenn::KeyManager::load_auth_file(const char *file_name) {
    if (mode == Mode::bank) return config::ERROR_INVALID_STATE;
    if (access(file_name, F_OK) == -1) {
        print_error("invalid auth file", "file does not exist");
        return config::ERROR_ATM_INVALID_AUTH_FILE;
    }

    auto bio_deleter = [](BIO *bio) { BIO_free(bio); };
    try {

        json auth;
        std::ifstream auth_file(file_name);
        auth_file >> auth;
        auth_file.close();

        auto ca_cert_pem = auth.at("ca_cert").get<std::string>();
        std::unique_ptr<BIO, decltype(bio_deleter)> ca_cert_bio(BIO_new(BIO_s_mem()), bio_deleter);
        BIO_write(ca_cert_bio.get(), ca_cert_pem.c_str(), (int) ca_cert_pem.length());
        if (!PEM_read_bio_X509(ca_cert_bio.get(), &ca_cert, 0, 0)) {
            print_error("failed to load CA certificate", ERR_error_string(ERR_get_error(), nullptr));
            return config::ERROR_ATM_INVALID_AUTH_FILE;
        }

        auto atm_key_pem = auth.at("atm_key").get<std::string>();
        std::unique_ptr<BIO, decltype(bio_deleter)> atm_key_bio(BIO_new(BIO_s_mem()), bio_deleter);
        BIO_write(atm_key_bio.get(), atm_key_pem.c_str(), (int) atm_key_pem.length());
        if (!PEM_read_bio_PrivateKey(atm_key_bio.get(), &atm_pkey, 0, 0)) {
            print_error("failed to load atm key", ERR_error_string(ERR_get_error(), nullptr));
            return config::ERROR_ATM_INVALID_AUTH_FILE;
        }
        atm_ecc_pkey = EVP_PKEY_get1_EC_KEY(atm_pkey);

        auto atm_cert_pem = auth.at("atm_cert").get<std::string>();
        std::unique_ptr<BIO, decltype(bio_deleter)> atm_cert_bio(BIO_new(BIO_s_mem()), bio_deleter);
        BIO_write(atm_cert_bio.get(), atm_cert_pem.c_str(), (int) atm_cert_pem.length());
        if (!PEM_read_bio_X509(atm_cert_bio.get(), &atm_cert, 0, 0)) {
            print_error("failed to load atm certificate", ERR_error_string(ERR_get_error(), nullptr));
            return config::ERROR_ATM_INVALID_AUTH_FILE;
        }
    } catch (const std::exception &e) {
        print_error("failed to load auth file", e.what());
        return config::ERROR_ATM_INVALID_AUTH_FILE;
    }

    mode = Mode::atm;
    ready = true;
    return 0;
}

SSL_CTX *impenn::KeyManager::create_tls_context() {
    if (!ready || mode == Mode::unknown) return nullptr;

    SSL_CTX *ctx = nullptr;

    try {
        if (mode == Mode::bank) {
            ctx = SSL_CTX_new(TLSv1_2_server_method());
            SSL_CTX_use_certificate(ctx, bank_cert);
            SSL_CTX_use_PrivateKey(ctx, bank_pkey);
        }

        if (mode == Mode::atm) {
            ctx = SSL_CTX_new(TLSv1_2_client_method());
            SSL_CTX_use_certificate(ctx, atm_cert);
            SSL_CTX_use_PrivateKey(ctx, atm_pkey);
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_ecdh_auto(ctx, 1);

        auto cert_store = X509_STORE_new();
        X509_STORE_add_cert(cert_store, ca_cert);
        SSL_CTX_set_cert_store(ctx, cert_store);
    } catch (const std::exception &e) {
        print_error("failed to create TLS context", e.what());
        if (ctx != nullptr) SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

int impenn::KeyManager::generate_card_file(const char *account, const char *file_name) {
    if (mode != Mode::atm) return config::ERROR_INVALID_STATE;
    if (!config::OVERWRITE_CARD_FILE && access(file_name, F_OK) != -1) {
        print_error("invalid card file", "file exists");
        return config::ERROR_ATM_CARD_FILE_EXIST;
    }

    auto signature = ECDSA_do_sign((unsigned char *) account, (int) strlen(account), atm_ecc_pkey);
    if (signature == nullptr) {
        print_error("failed to sign account", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    int max_der_length = ECDSA_size(atm_ecc_pkey);
    std::unique_ptr<unsigned char[]> der(new unsigned char[max_der_length]);
    auto der_ptr = der.get();
    auto der_length = i2d_ECDSA_SIG(signature, &der_ptr);
    if (der_length == 0) {
        print_error("failed to encode signature", ERR_error_string(ERR_get_error(), nullptr));
        return config::ERROR_UNKNOWN;
    }

    try {
        ECDSA_SIG_free(signature);

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < der_length; i++) {
            ss << std::setw(2) << (int) der[i] << " ";
        }

        std::ofstream card_file(file_name);
        card_file << ss.str();
        card_file.close();
    } catch (const std::exception &e) {
        print_error("failed to save card file", e.what());
        return config::ERROR_UNKNOWN;
    }

    return 0;
}

int impenn::KeyManager::verify_card_file(const char *account, const char *file_name) {
    if (mode != Mode::atm) return config::ERROR_INVALID_STATE;
    if (access(file_name, F_OK) == -1) {
        print_error("invalid card file", "file does not exist");
        return config::ERROR_ATM_INVALID_CARD_FILE;
    }

    try {
        std::ifstream size_checker(file_name, std::ios::binary | std::ios::ate);
        auto file_size = size_checker.tellg();
        size_checker.close();
        if (file_size > config::MAX_CARD_FILE_LENGTH) {
            print_error("failed to read card file", "file size exceeds maximum");
            return config::ERROR_ATM_INVALID_CARD_FILE;
        }

        std::ifstream card_file(file_name);
        std::stringstream ss;
        ss << card_file.rdbuf();
        card_file.close();

        auto der_length = ((int) file_size + 1) / 3;
        std::unique_ptr<unsigned char[]> der(new unsigned char[der_length]);
        auto der_ptr = der.get();
        unsigned int c;
        int i = 0;
        while (ss >> std::hex >> c) der[i++] = (unsigned char) c;

        auto signature = d2i_ECDSA_SIG(nullptr, (const unsigned char **) &der_ptr, der_length);
        if (signature == nullptr) {
            print_error("failed to convert signature to DER", ERR_error_string(ERR_get_error(), nullptr));
            return config::ERROR_ATM_INVALID_CARD_FILE;
        }

        auto status = ECDSA_do_verify((unsigned char *) account, (int) strlen(account), signature, atm_ecc_pkey);
        if (status != 1) {
            print_error("failed to verify signature", ERR_error_string(ERR_get_error(), nullptr));
            return config::ERROR_ATM_INVALID_CARD_FILE;
        }
    } catch (const std::exception &e) {
        print_error("failed to read card file", e.what());
        return config::ERROR_UNKNOWN;
    }

    return 0;
}

int impenn::KeyManager::delete_card_file(const char *file_name) {
    if (mode != Mode::atm) return config::ERROR_INVALID_STATE;
    if (access(file_name, F_OK) == -1) {
        print_error("invalid card file", "file does not exist");
        return config::ERROR_ATM_INVALID_CARD_FILE;
    }

    if (std::remove(file_name) != 0) return config::ERROR_UNKNOWN;
    return 0;
}

void impenn::KeyManager::add_name_entry(X509_NAME *name, const char *tag, const unsigned char *value) {
    X509_NAME_add_entry_by_txt(name, tag, MBSTRING_ASC, value, -1, -1, 0);
}

std::string impenn::KeyManager::get_key_pem(EVP_PKEY *key) {
    std::string pem;

    try {
        auto bio_deleter = [](BIO *bio) { BIO_free(bio); };
        std::unique_ptr<BIO, decltype(bio_deleter)> bio(BIO_new(BIO_s_mem()), bio_deleter);

        if (PEM_write_bio_PrivateKey(bio.get(), key,
                                     nullptr, nullptr, 0, nullptr, nullptr) < 0) {
            print_error("failed to write key to bio", ERR_error_string(ERR_get_error(), nullptr));
            return "";
        }

        size_t length = BIO_ctrl_pending(bio.get());
        auto buffer = std::unique_ptr<char[]>(new char[length]);
        if (BIO_read(bio.get(), buffer.get(), (int) length) < 0) {
            print_error("failed to read key from bio", ERR_error_string(ERR_get_error(), nullptr));
            return "";
        }

        pem = std::string(static_cast<const char *>(buffer.get()), length);
    } catch (const std::exception &e) {
        return "";
    }

    return pem;
}

std::string impenn::KeyManager::get_cert_pem(X509 *cert) {
    std::string pem;

    try {
        auto bio_deleter = [](BIO *bio) { BIO_free(bio); };
        std::unique_ptr<BIO, decltype(bio_deleter)> bio(BIO_new(BIO_s_mem()), bio_deleter);

        if (PEM_write_bio_X509(bio.get(), cert) < 0) {
            print_error("failed to write cert to bio", ERR_error_string(ERR_get_error(), nullptr));
            return "";
        }

        size_t length = BIO_ctrl_pending(bio.get());
        auto buffer = std::unique_ptr<char[]>(new char[length]);
        if (BIO_read(bio.get(), buffer.get(), (int) length) < 0) {
            print_error("failed to read cert from bio", ERR_error_string(ERR_get_error(), nullptr));
            return "";
        }

        pem = std::string(static_cast<const char *>(buffer.get()), length);
    } catch (const std::exception &e) {
        return "";
    }

    return pem;
}

void impenn::KeyManager::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[KeyManager]: " << message << " - " << error << std::endl;
    }
}

void impenn::KeyManager::dump_crypto() {
    if (!ready) return;
    std::cerr << "--- Cryptographic Dump ---" << std::endl;

    if (mode == Mode::bank) {
        std::cerr << "+++ CA Root +++" << std::endl;
        std::cerr << get_key_pem(ca_pkey) << std::endl;
        X509_print_fp(stderr, ca_cert);

        std::cerr << "+++ Bank +++" << std::endl;
        std::cerr << get_key_pem(bank_pkey) << std::endl;
        X509_print_fp(stderr, bank_cert);

        std::cerr << "+++ ATM +++" << std::endl;
        std::cerr << get_key_pem(atm_pkey) << std::endl;
        X509_print_fp(stderr, atm_cert);
    }

    if (mode == Mode::atm) {
        std::cerr << "+++ CA Root +++" << std::endl;
        X509_print_fp(stderr, ca_cert);

        std::cerr << "+++ ATM +++" << std::endl;
        std::cerr << get_key_pem(atm_pkey) << std::endl;
        X509_print_fp(stderr, atm_cert);
    }

    std::cerr << "--- Cryptographic Dump ---" << std::endl;
}
