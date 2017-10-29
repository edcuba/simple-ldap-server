#include "filter.h"
#include "cli.h"
#include "csv.h"
#include "dataset.h"
#include "server.h"
#include <vector>

using namespace std;

#define CHECK(data, val) \
    if (data != val)     \
    throw runtime_error ("Failed to parse filter")

/**
 * Apply filters on dataset
 **/
dataSet
ldapContext::filterData ()
{
    dataSet dataset;
    if (search && data) {
        for (auto &e : *data) {
            dataset.insert (&e);
        }
        filterDataSet (dataset, search->filter);
    }
    return dataset;
}

/**
 * Parse equalityMatch filter
 **/
void
ldapContext::parseFilterEq (ldapFilter &filter)
{
    // parse attribute
    unsigned char data = getByte ();
    CHECK (data, 0x04);
    filter.attributeDesc = readAttr ();

    // parse value
    data = getByte ();
    CHECK (data, 0x04);
    filter.assertionValue = readAttr ();
}

/**
 * Parse OR, AND or NOT filter
 **/
void
ldapContext::parseFilterOrAndNot (ldapFilter &filter)
{
    // use recursion to parse subfilters
    size_t remaining = filter.len;

    printD ("[OR/AND/NOT] Parsing filter of length: " << remaining);

    while (remaining > 0) {
        ldapFilter sub = parseSubFilter ();
        printD ("[OR/AND/NOT] Got filter of length: " << sub.len << " remaining: " << remaining);
        remaining -= sub.len;
        remaining -= 2; // structure data
        filter.subs.push_back (sub);
    }
}

void
ldapContext::parseFilterSub (ldapFilter &filter)
{
    printE ("filterSub not supported");
}

/**
 * Process single filter
 **/
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
            parseFilterOrAndNot (filter);
            break;
        case FILTER_AND:
            filter.type = FILTER_AND;
            parseFilterOrAndNot (filter);
            break;
        case FILTER_NOT:
            filter.type = FILTER_NOT;
            parseFilterOrAndNot (filter);
            break;
        case FILTER_SUB:
            filter.type = FILTER_SUB;
            parseFilterSub (filter);
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
ldapMessage
ldapContext::parseFilter ()
{
    printD ("Parsing filters");

    try {
        search->filter = parseSubFilter ();
    } catch (...) {
        return ldapMessage (ERR_FILTER);
    }

    return processSearchDescList ();
}
