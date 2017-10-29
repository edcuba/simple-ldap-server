using namespace std;

#include "dataset.h"

/**
 * equalityMatch implementation
 **/
void
filterEq (dataSet &data, ldapFilter &filter)
{
    dataSet result;
    for (auto e : data) {
        auto res = e->find (filter.attributeDesc);
        if (res != e->end () && res->second == filter.assertionValue) {
            result.insert (e);
        }
    }
    data.swap (result);
}

void
filterOr (dataSet &data, ldapFilter &filter)
{
    dataSet result;
    for (auto &f : filter.subs) {
        dataSet d (data);
        filterDataSet (d, f);
        for (auto e : d) {
            result.insert (e);
        }
    }
    data.swap (result);
}

void
filterAnd (dataSet &data, ldapFilter &filter)
{
    for (auto &f : filter.subs) {
        filterDataSet (data, f);
    }
}

void
filterNot (dataSet &data, ldapFilter &filter)
{
    dataSet result (data);
    // there is always only one filter
    for (auto &f : filter.subs) {
        filterDataSet (result, f);
    }
    // drop positive matches
    for (auto e : result) {
        data.erase (e);
    }
}

/**
 * Apply single filter on dataset
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
        default:
            printE ("Filter " << filter.type << " not implemented yet");
            break;
    }
}
