/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: The imPENNetrables
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_TYPES_H
#define IMPENNETRABLES_TYPES_H

#include <gmpxx.h>
namespace impenn {

enum class MessageType {
    client_new_account, client_balance, client_deposit, client_withdraw,
    bank_success, bank_failed,
    unknown
};

struct Account{
	std::string name;
	mpz_class dollars;
	uint8_t cents;
};

}

#endif //IMPENNETRABLES_TYPES_H
