/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Grayson Honan
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_BANK_DRIVER_H
#define IMPENNETRABLES_BANK_DRIVER_H

#include <memory>

#include "database.h"
#include "talker.h"

typedef struct AccountData AccountData;

namespace impenn {
namespace bank {

class Driver {
public:
    explicit Driver(std::shared_ptr<Talker> talker, std::shared_ptr<Database> db);

    ~Driver() = default;

    void start();

private:
    std::shared_ptr<Talker> talker;
    std::shared_ptr<Database> db;

    int64_t parseDollars(const char *number);

    int16_t parseCents(const char *number);

    int sendResult(bool result, impenn::Account *accountReturn);

    void printResult(impenn::Account *accountReturn, impenn::MessageType type);

    void print_error(const char *message, const char *error);
};

}
}

#endif //IMPENNETRABLES_BANK_DRIVER_H
