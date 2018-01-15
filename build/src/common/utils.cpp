/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#include "utils.h"

#include <cstring>

#include "config.h"

std::string impenn::utils::remove_amount_quotes(std::string input) {
    size_t pos = 0;
    size_t sub_pos = 0;
    if ((pos = input.find(config::JSON_KEY_INIT_BALANCE)) != std::string::npos) {
        sub_pos = pos + strlen(config::JSON_KEY_INIT_BALANCE) + 2;
    } else if ((pos = input.find(config::JSON_KEY_DEPOSIT)) != std::string::npos) {
        sub_pos = pos + strlen(config::JSON_KEY_DEPOSIT) + 2;
    } else if ((pos = input.find(config::JSON_KEY_WITHDRAW)) != std::string::npos) {
        sub_pos = pos + strlen(config::JSON_KEY_WITHDRAW) + 2;
    } else if ((pos = input.find(config::JSON_KEY_BALANCE)) != std::string::npos) {
        sub_pos = pos + strlen(config::JSON_KEY_BALANCE) + 2;
    }

    if (sub_pos > 0) {
        input.erase(input.find('"', sub_pos), 1);
        input.erase(input.find('"', sub_pos), 1);
    }

    return input;
}