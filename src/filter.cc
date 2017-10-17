#include "filter.h"

/**
 * Parse filter from message into ldapFilter structure
 * Supported operations:
 *  - and (0xA0)
 *  - or  (0xA1)
 *  - not (0xA2)
 *  - equalityMatch (0xA3)
 *  - substrings    (0xA4)
 *
 * @context ldap message context
 * @return filter structure
 **/
ldapFilter *
parseFilter (ldapContext *context)
{
    ldapFilter *filter = new ldapFilter ();

    unsigned char data = getByte (context);

    switch (data) {
        case FILTER_OR:
        case FILTER_AND:
        case FILTER_NOT:
        case FILTER_SUB:
        case FILTER_EQ:
            break;
    }

    return filter;
}
