#ifndef FILTER_H
#define FILTER_H

#include <cstring>
#include <string>
#include <vector>

using namespace std;

/**
 * Supported filter types
 **/
typedef enum {
    FILTER_UNKNOWN = 0,
    FILTER_AND = 0xA0,
    FILTER_OR = 0xA1,
    FILTER_NOT = 0xA2,
    FILTER_SUB = 0xA4,
    FILTER_EQ = 0xA3
} filterType;

/**
 * Substring types
 **/
typedef enum { SUB_INITIAL = 0x80, SUB_ANY = 0x81, SUB_FINAL = 0x82 } subStringType;

/**
 * Substring representation object
 **/
class subString
{
  public:
    subString (subStringType t, const string &s);
    subStringType type;
    string value;
};

/**
 * Object representation of filter
 **/
class ldapFilter
{
  public:
    size_t len = 0;
    filterType type = FILTER_UNKNOWN;
    string attributeDesc;
    string assertionValue;
    vector<ldapFilter> subFilters;
    vector<subString> subStrings;
};

#endif
