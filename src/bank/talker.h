/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_BANK_TALKER_H
#define IMPENNETRABLES_BANK_TALKER_H

#include <memory>

#include <openssl/ssl.h>

#include "common/config.h"

namespace impenn {
namespace bank {

class Talker {
public:
    Talker(int fd, std::string address);

    ~Talker();

    int accept(SSL_CTX *ctx);

    std::string read_message(int *status);

    int write_message(std::string message);

private:
    int fd;
    std::string address;
    SSL *ssl;

    char tls_buffer[config::MAX_TLS_BUFFER_SIZE];
    int bytes_in_buffer;

    void print_error(const char *message, const char *error);

    void print_error(const char *message);
};

}
}

#endif //IMPENNETRABLES_BANK_TALKER_H
