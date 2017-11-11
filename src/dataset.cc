using namespace std;

#include "dataset.h"

/**
 * Convert string to lowercase
 **/
static string
toLC (const string &s)
{
    string res;
    for (auto c : s) {
        res += tolower (c);
    }
    return res;
}

/**
 * equalityMatch implementation
 **/
void
filterEq (dataSet &data, ldapFilter &filter)
{
    dataSet result;

    // for every entry in dataset
    for (entry *e : data) {

        // find required attribute and compare it with desired value
        string desc = toLC (filter.attributeDesc);
        auto res = e->find (desc);
        if (res != e->end () && toLC (res->second) == toLC (filter.assertionValue)) {
            // if positive, than save the entry
            result.insert (e);
        }
    }
    data.swap (result);
}

/**
 * subString implementation
 **/
void
filterSub (dataSet &data, ldapFilter &filter)
{
    dataSet result;

    // for entry in database
    for (entry *e : data) {

        // get requested attribute
        string desc = toLC (filter.attributeDesc);
        auto res = e->find (desc);

        if (res != e->end ()) {
            // object contains requested attribute

            bool match = true;
            const string &v = toLC (res->second);

            // position in string - for proper any filter functionality
            size_t pos = 0;

            // check substrings
            for (subString &s : filter.subStrings) {

                string k = toLC (s.value);

                if (s.type == SUB_INITIAL) {
                    // substring on the beggining
                    pos = v.find (k);
                    if (pos != 0) {
                        match = false;
                        break;
                    }
                    pos += k.size ();
                } else if (s.type == SUB_ANY) {
                    // substring anywhere
                    pos = v.find (k, pos);
                    if (pos == string::npos) {
                        match = false;
                        break;
                    }
                    pos += k.size ();
                } else { // SUB_FINAL
                    // substring on the end
                    if (v.find (k, v.size () - k.size ()) == string::npos) {
                        match = false;
                        break;
                    }
                }
            }

            if (match) {
                result.insert (e);
            }
        }
    }
    data.swap (result);
}

/**
 * Implementation of OR filter
 **/
void
filterOr (dataSet &data, ldapFilter &filter)
{
    dataSet result;

    // for each subfilter
    for (auto &f : filter.subFilters) {
        dataSet d (data);
        // process subfilter
        filterDataSet (d, f);

        // create conjunction
        for (auto e : d) {
            result.insert (e);
        }
    }
    data.swap (result);
}

/**
 * Implementation of AND filter
 **/
void
filterAnd (dataSet &data, ldapFilter &filter)
{
    // apply all the filters on the dataset
    for (auto &f : filter.subFilters) {
        filterDataSet (data, f);
    }
}

/**
 * Implementation of NOT filter
 **/
void
filterNot (dataSet &data, ldapFilter &filter)
{
    dataSet result (data);
    // there is always only one filter
    for (auto &f : filter.subFilters) {
        // apply the filter
        filterDataSet (result, f);
    }
    // drop positive matches
    for (auto e : result) {
        data.erase (e);
    }
}

/**
 * Apply filter on dataset
 *  including all of its subfilters recursively
 **/
void
filterDataSet (dataSet &data, ldapFilter &filter)
{
    switch (filter.type) {
        case FILTER_EQ:
            filterEq (data, filter);
            break;
        case FILTER_OR:
            filterOr (data, filter);
            break;
        case FILTER_AND:
            filterAnd (data, filter);
            break;
        case FILTER_NOT:
            filterNot (data, filter);
            break;
        case FILTER_SUB:
            filterSub (data, filter);
            break;
        default:
            break;
    }
}
