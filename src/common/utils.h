/* ---------------------------------------------------------------------------
* This file is part of imPENNetrables
*
* @author: Hung Nguyen
* --------------------------------------------------------------------------*/
#ifndef IMPENNETRABLES_UTILS_H
#define IMPENNETRABLES_UTILS_H

#include <string>

namespace impenn {

class utils {
public:
    static std::string remove_amount_quotes(std::string input);
};

}

#endif //IMPENNETRABLES_UTILS_H
