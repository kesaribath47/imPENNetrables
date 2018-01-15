/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Grayson Honan
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_BANK_SANITIZER_H
#define IMPENNETRABLES_BANK_SANITIZER_H

#include <json/json.hpp>

#include "common/config.h"
#include "common/types.h"

namespace impenn {
namespace bank {

class Sanitizer {
public:
    impenn::MessageType check_command(std::string input);

private:
    impenn::MessageType check_deposit_cmd(nlohmann::json deposit);

    impenn::MessageType check_withdraw_cmd(nlohmann::json withdraw);

    impenn::MessageType check_new_account_cmd(nlohmann::json new_account);

    impenn::MessageType check_balance_cmd(nlohmann::json balance);

    impenn::MessageType check_regular_cmd(impenn::MessageType type,
                                          std::string account,
                                          std::string dollars,
                                          std::string cents);

    void print_error(const char *message);
};

}
}

#endif //IMPENNETRABLES_BANK_SANITIZER_H
