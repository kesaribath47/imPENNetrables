/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#include "client.h"

#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

#include "common/key_manager.h"

using namespace impenn;
using namespace impenn::atm;

impenn::atm::Client::Client()
        : bank_fd(0), ctx(nullptr), ssl(nullptr), connected(false), bytes_in_buffer(0) {

}

impenn::atm::Client::~Client() {
    shutdown();
}

int impenn::atm::Client::connect_to_bank(const char *bank_address, int bank_port) {
    if (!KeyManager::get().is_ready()) {
        print_error("failed to connect to bank", "KeyManager is not ready");
        return config::ERROR_INVALID_STATE;
    }

    try {
        if (ctx == nullptr) {
            ctx = KeyManager::get().create_tls_context();
            if (ctx == nullptr) {
                print_error("failed to connect to bank", "cannot create context");
                return config::ERROR_ATM_INVALID_AUTH_FILE;
            }
        }

        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ssl = SSL_new(ctx);
        if (ssl == nullptr) {
            print_error("failed to connect to bank", "cannot create TLS handler");
            return config::ERROR_ATM_INVALID_AUTH_FILE;
        }
    } catch (const std::exception &e) {
        print_error("failed to connect to bank", "cannot initialize TLS environment");
        exit(config::ERROR_UNKNOWN);
    }

    bank_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (bank_fd < 0) {
        print_error("failed to connect to bank", "cannot open socket");
        return config::ERROR_ATM_FAILED_CONNECT;
    }

    struct timeval timeout;
    timeout.tv_sec = config::SOCKET_TIMEOUT;
    timeout.tv_usec = 0;

    setsockopt(bank_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
    setsockopt(bank_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

    struct sockaddr_in bank_addr;
    bzero(&bank_addr, sizeof(bank_addr));
    bank_addr.sin_family = AF_INET;
    bank_addr.sin_port = htons(bank_port);
    inet_pton(AF_INET, bank_address, &bank_addr.sin_addr);
    if (connect(bank_fd, (struct sockaddr *) &bank_addr, sizeof(bank_addr)) < 0) {
        print_error("failed to connect to bank", strerror(errno));
        return config::ERROR_ATM_FAILED_CONNECT;
    }

    SSL_set_fd(ssl, bank_fd);
    int status = 0;
    if ((status = SSL_connect(ssl)) != 1) {
        print_error("failed to connect to bank", std::to_string(SSL_get_error(ssl, status)).c_str());
        return config::ERROR_ATM_FAILED_CONNECT;
    }

    connected = true;
    return 0;
}

std::string impenn::atm::Client::read_message(int *status) {
    std::string message;
    int lfpos = -1;

    while (true) {
        for (int i = 0; i < bytes_in_buffer; ++i) {
            if (tls_buffer[i] == '\n') {
                lfpos = i;
                break;
            }
        }

        if (lfpos >= 0) break;

        if (bytes_in_buffer >= config::MAX_TLS_BUFFER_SIZE) {
            print_error("failed to read message", "buffer overflowed");
            if (status != nullptr) *status = config::ERROR_PROTOCOL;
            return "";
        }

        int bytes_read = SSL_read(ssl, &tls_buffer[bytes_in_buffer], config::MAX_TLS_BUFFER_SIZE - bytes_in_buffer);
        if (bytes_read < 0) {
            print_error("failed to read message", std::to_string(SSL_get_error(ssl, bytes_read)).c_str());
            if (status != nullptr) *status = config::ERROR_PROTOCOL;
            return "";
        }
        if (bytes_read == 0) {
            if (status != nullptr) *status = 0;
            return "";
        }

        bytes_in_buffer += bytes_read;
    }

    message = std::string(tls_buffer, lfpos);

    for (int i = lfpos; i < bytes_in_buffer; ++i) tls_buffer[i - lfpos] = tls_buffer[i];
    bytes_in_buffer -= lfpos;

    *status = 0;
    return message;
}

int impenn::atm::Client::write_message(std::string message) {
    size_t length = message.length() + 1;
    message += "\n";
    size_t wpos = 0;

    while (wpos < length) {
        int bytes_write = SSL_write(ssl, &message.c_str()[wpos], (int) (length - wpos));
        if (bytes_write <= 0) {
            print_error("failed to write message", std::to_string(SSL_get_error(ssl, bytes_write)).c_str());
            return config::ERROR_UNKNOWN;
        }

        wpos += bytes_write;
    }

    return 0;
}

void impenn::atm::Client::shutdown() {
    if (ssl != nullptr) {
        SSL_shutdown(ssl);
        SSL_free(ssl);

        close(bank_fd);
    }
    if (ctx != nullptr) SSL_CTX_free(ctx);
}

void impenn::atm::Client::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[ATM]: " << message << " - " << error << std::endl;
    }
}