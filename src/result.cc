#include "result.h"

ldapResult::ldapResult (ldapResultType t)
{
    type = t;
}

const string
ldapResult::dump () const
{
    switch (type) {
        default:
            break;
    }
    return resultSucessData;
};
