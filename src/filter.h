#ifndef FILTER_H
#define FILTER_H

#define FILTER_AND 0xA0
#define FILTER_OR 0xA1
#define FILTER_NOT 0xA2
#define FILTER_SUB 0xA4
#define FILTER_EQ 0xA3

class ldapFilter
{
};

#include "ldap.h"

ldapFilter *
parseFilter (ldapContext *context);

#endif
