#ifndef FILTER_H
#define FILTER_H

#include <cstring>
#include <string>
#include <vector>

using namespace std;

typedef enum {
    FILTER_UNKNOWN = 0,
    FILTER_AND = 0xA0,
    FILTER_OR = 0xA1,
    FILTER_NOT = 0xA2,
    FILTER_SUB = 0xA4,
    FILTER_EQ = 0xA3
} filterType;

class ldapFilter
{
  public:
    unsigned char len = 0;
    filterType type = FILTER_UNKNOWN;
    string attributeDesc;
    string assertionValue;
    vector<ldapFilter> subs;
};

#include "ldap.h"

#endif
