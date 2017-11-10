#include "result.h"

/**
 * ldapResult constructor
 *  type is set to allow support of muliple result codes if needed
 **/
ldapResult::ldapResult (ldapResultType t)
{
    type = t;
}

/**
 * Dump result code into an integer
 *   For now just success code is needed
 **/
const string
ldapResult::dump () const
{
    return resultSucessData;
};
