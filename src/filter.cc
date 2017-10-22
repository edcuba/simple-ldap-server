#include "filter.h"
#include "cli.h"
#include "server.h"

using namespace std;

#define CHECK(data, val) \
    if (data != val)     \
    throw runtime_error ("Failed to parse filter")

void
ldapContext::parseFilterEq (ldapFilter &filter)
{
    // parse attribute
    unsigned char data = getByte ();
    CHECK (data, MSG_PROP);
    filter.attributeDesc = readAttr ();

    // parse value
    data = getByte ();
    CHECK (data, MSG_PROP);
    filter.assertionValue = readAttr ();
}

ldapFilter
ldapContext::parseSubFilter ()
{
    // get filter type
    unsigned char data = getByte ();

    // get filter length
    ldapFilter filter;
    filter.len = getByte ();

    switch (data) {
        case FILTER_OR:
            filter.type = FILTER_OR;
            break;
        case FILTER_AND:
            filter.type = FILTER_AND;
            break;
        case FILTER_NOT:
            filter.type = FILTER_NOT;
        case FILTER_SUB:
            filter.type = FILTER_SUB;
            break;
        case FILTER_EQ:
            filter.type = FILTER_EQ;
            parseFilterEq (filter);
            break;
    }

    return filter;
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
ldapResponse
ldapContext::parseFilter ()
{
    printD ("Parsing filters");

    try {
        search->filter = parseSubFilter ();
    } catch (...) {
        return ldapError (ERR_FILTER);
    }

    return processSearchDescList ();
}
