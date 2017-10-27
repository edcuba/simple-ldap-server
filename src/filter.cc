#include "filter.h"
#include "cli.h"
#include "csv.h"
#include "server.h"
#include <vector>

using namespace std;

#define CHECK(data, val) \
    if (data != val)     \
    throw runtime_error ("Failed to parse filter")

/**
 * equalityMatch implementation
 **/
static void
filterEq (vector<entry *> &dataset, ldapFilter &filter)
{
    vector<entry *> result;
    for (auto e : dataset) {
        auto res = e->find (filter.attributeDesc);
        if (res != e->end () && res->second == filter.assertionValue) {
            result.push_back (e);
        }
    }
    dataset.swap (result);
}

/**
 * Apply single filter on dataset
 **/
static void
filterDataSet (vector<entry *> &dataset, ldapFilter &filter)
{
    switch (filter.type) {
        case FILTER_EQ:
            filterEq (dataset, filter);
            break;
        default:
            break;
    }
}

/**
 * Apply filters on dataset
 **/
vector<entry *>
ldapContext::filterData ()
{
    vector<entry *> dataset;
    if (search && data) {
        for (auto &e : *data) {
            dataset.push_back (&e);
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
    CHECK (data, MSG_PROP);
    filter.attributeDesc = readAttr ();

    // parse value
    data = getByte ();
    CHECK (data, MSG_PROP);
    filter.assertionValue = readAttr ();
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
