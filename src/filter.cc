#include "filter.h"
#include "cli.h"
#include "csv.h"
#include "dataset.h"
#include "server.h"
#include <vector>

using namespace std;

// helper function for value comparison
template <typename T1, typename T2>
inline void
CHECK (T1 data, T2 val)
{
    if (data != val)
        throw runtime_error ("Failed to parse filter");
}

// subString constructor
subString::subString (subStringType t, const string &s)
{
    type = t;
    value = s;
}

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

    printD ("Parsing a filter of length: " << remaining);

    while (remaining > 0) {
        ldapFilter sub = parseSubFilter ();
        printD ("Got a filter of length: " << sub.len << " remaining: " << remaining);
        remaining -= sub.len;
        remaining -= 2; // structure data
        filter.subFilters.push_back (sub);
    }
}

/**
 * Parse initial or any substring and proceed
 **/
void
ldapContext::parseFilterSubSub (ldapFilter &filter, size_t remaining, subStringType t)
{
    printD ("Parsing initial subFilter");

    // store actual amount of received bytes
    size_t diff = received;

    filter.subStrings.push_back (subString (t, readAttr ()));

    // find out remaining length
    diff = received - diff;
    remaining -= diff;

    // no more substrings
    if (remaining < 2) {
        return;
    }

    // read next filter type
    unsigned char data = getByte ();
    remaining--;

    switch (data) {
        case SUB_ANY:
            parseFilterSubSub (filter, remaining, SUB_ANY);
            return;
        case SUB_FINAL:
            parseFilterSubFinal (filter);
            return;
    }
}

/**
 * Parse final substring and proceed
 **/
void
ldapContext::parseFilterSubFinal (ldapFilter &filter)
{
    printD ("Parsing final subFilter");
    filter.subStrings.push_back (subString (SUB_FINAL, readAttr ()));
}

/**
 * Parse substring filter
 **/
void
ldapContext::parseFilterSub (ldapFilter &filter)
{
    printD ("Parsing subFilter");

    // parse attribute
    unsigned char data = getByte ();
    CHECK (data, 0x04);
    filter.attributeDesc = readAttr ();

    // substrings
    data = getByte ();
    CHECK (data, 0x30);

    // length of substring structure
    size_t remaining = readLength ();

    data = getByte ();

    remaining--;

    switch (data) {
        case SUB_INITIAL:
            parseFilterSubSub (filter, remaining, SUB_INITIAL);
            return;
        case SUB_ANY:
            parseFilterSubSub (filter, remaining, SUB_ANY);
            return;
        case SUB_FINAL:
            parseFilterSubFinal (filter);
            return;
    }
    throw runtime_error ("Invalid subFilter type");
}

/**
 * Parse PRESENT filter
 **/
void
ldapContext::parseFilterPresent (ldapFilter &filter)
{
    for (size_t i = 0; i < filter.len; ++i) {
        filter.attributeDesc += getByte ();
    }
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
    filter.len = readLength ();

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
        case FILTER_PRESENT:
            filter.type = FILTER_PRESENT;
            parseFilterPresent (filter);
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
