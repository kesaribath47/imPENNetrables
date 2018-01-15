/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_ATM_CLIENT_H
#define IMPENNETRABLES_ATM_CLIENT_H

#include <atomic>

#include <openssl/ssl.h>

#include "common/config.h"

namespace impenn {
namespace atm {

class Client {
public:
    Client();

    ~Client();

    int connect_to_bank(const char *bank_address, int bank_port);

    std::string read_message(int *status);

    int write_message(std::string message);

private:
    SSL_CTX *ctx;
    SSL *ssl;
    int bank_fd;

    std::atomic_bool connected;

    char tls_buffer[config::MAX_TLS_BUFFER_SIZE];
    int bytes_in_buffer;

    void print_error(const char *message, const char *error);
};

}
}

#endif //IMPENNETRABLES_ATM_CLIENT_H
