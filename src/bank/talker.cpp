/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#include "talker.h"

#include <iostream>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/err.h>

using namespace impenn;
using namespace impenn::bank;

impenn::bank::Talker::Talker(int fd, const std::string address)
        : fd(fd), address(address), ssl(nullptr), bytes_in_buffer(0) {

}

impenn::bank::Talker::~Talker() {
    if (ssl != nullptr) {
        if (SSL_shutdown(ssl) > 0) {
            SSL_free(ssl);
        }

        std::ostringstream os;
        os << "closing " << address;
        print_error(os.str().c_str());

        close(fd);
    }
}

int impenn::bank::Talker::accept(SSL_CTX *ctx) {
    struct timeval timeout;
    timeout.tv_sec = config::SOCKET_TIMEOUT;
    timeout.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    int status = 0;
    if ((status = SSL_accept(ssl)) != 1) {
        print_error("failed to accept TLS connection", std::to_string(SSL_get_error(ssl, status)).c_str());
        return config::ERROR_UNKNOWN;
    }

    return 0;
}

std::string impenn::bank::Talker::read_message(int *status) {
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

    for (int i = lfpos + 1; i < bytes_in_buffer; ++i) tls_buffer[i - (lfpos + 1)] = tls_buffer[i];
    bytes_in_buffer -= (lfpos + 1);

    *status = 0;
    return message;
}

int impenn::bank::Talker::write_message(std::string message) {
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

void impenn::bank::Talker::print_error(const char *message, const char *error) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Talker-" << std::this_thread::get_id() << "]: " << message << " - " << error << std::endl;
    }
}

void impenn::bank::Talker::print_error(const char *message) {
    if (config::VERBOSE) {
        std::cerr << "[BANK-Talker-" << std::this_thread::get_id() << "]: " << message << std::endl;
    }
}