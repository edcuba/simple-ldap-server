using namespace std;

#include "dataset.h"

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
        auto res = e->find (filter.attributeDesc);
        if (res != e->end () && res->second == filter.assertionValue) {
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
        auto res = e->find (filter.attributeDesc);

        if (res != e->end ()) {
            // object contains requested attribute

            bool match = true;
            const string &v = res->second;

            // check substrings
            for (subString &s : filter.subStrings) {

                if (s.type == SUB_INITIAL) {
                    // substring on the beggining
                    if (v.find (s.value) != 0) {
                        match = false;
                        break;
                    }
                } else if (s.type == SUB_ANY) {
                    // substring anywhere
                    if (v.find (s.value) == string::npos) {
                        match = false;
                        break;
                    }
                } else { // SUB_FINAL
                    // substring on the end
                    if (v.find (s.value, v.size () - s.value.size ()) == string::npos) {
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
