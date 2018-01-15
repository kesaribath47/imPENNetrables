/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Grayson Honan
* --------------------------------------------------------------------------*/

#ifndef IMPENNETRABLES_BANK_DATABASE_H
#define IMPENNETRABLES_BANK_DATABASE_H

#include <mutex>
#include <string>
#include <gmpxx.h>
#include <map>
#include "common/config.h"
#include "common/types.h"

namespace impenn {
namespace bank {

class Database {
public:
    bool deposit(std::string account, uint32_t dollars, uint8_t cents, impenn::Account *accountReturn);

    bool withdraw(std::string account, uint32_t dollars, uint8_t cents, impenn::Account *accountReturn);

    bool create_account(std::string account, uint32_t dollars, uint8_t cents, impenn::Account *accountReturn);

    bool balance(std::string account, impenn::Account *accountReturn);

private:
    std::map<std::string, mpz_class> dbDollars;
    std::map<std::string, uint8_t> dbCents;
    std::mutex dbLock;

    void print_error(const char *message, const char *error);

    void print_error(const char *message);
};

}
}

#endif //IMPENNETRABLES_BANK_DATABASE_H
