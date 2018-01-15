/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_BANK_SERVER_H
#define IMPENNETRABLES_BANK_SERVER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#include "common/config.h"
#include "database.h"
#include "talker.h"

namespace impenn {
namespace bank {

class Server {
public:
    Server();

    ~Server();

    int start(int port);

    static void shutdown(int sig);
private:
    SSL_CTX *ctx;

    static std::vector<std::thread> running_threads;
    static std::mutex thread_mutex;

    static void worker(std::shared_ptr<Talker> talker, std::shared_ptr<Database> db);

    static std::atomic_bool interrupted;

    void print_error(const char *message, const char *error);

    void print_error(const char *message);
};

}
}

#endif //IMPENNETRABLES_BANK_SERVER_H
