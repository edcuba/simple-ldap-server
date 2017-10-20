#include "filter.h"
#include "cli.h"
#include "server.h"

static ldapResponse *
parseFilterEq (ldapContext *context)
{
    ldapFilter &filter = context->search->filter;

    // parse attribute
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_PROP);
    filter.attributeDesc = readAttr (context);

    // parse value
    data = getByte (context);
    EXPECT (context, data, MSG_PROP);
    filter.assertionValue = readAttr (context);

    return processSearchDescList (context);
}

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
 * @return True if operation was successfull
 **/
ldapResponse *
parseFilter (ldapContext *context)
{
    printD ("Parsing filter");

    // get filter type
    unsigned char data = getByte (context);

    // get filter length
    context->search->filter.len = getByte (context);

    switch (data) {
        case FILTER_OR:
        case FILTER_AND:
        case FILTER_NOT:
        case FILTER_SUB:
            break;
        case FILTER_EQ:
            return parseFilterEq (context);
    }

    return ldapError (context, ERR_FILTER);
}
