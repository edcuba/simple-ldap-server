#ifndef DATASET_H
#define DATASET_H

#include "csv.h"
#include <unordered_set>

using namespace std;

typedef unordered_set<entry *> dataSet;

#include "filter.h"
#include "ldap.h"

void
filterEq (dataSet &data, ldapFilter &filter);

void
filterOr (dataSet &data, ldapFilter &filter);

void
filterAnd (dataSet &data, ldapFilter &filter);

void
filterNot (dataSet &data, ldapFilter &filter);

void
filterSub (dataSet &data, ldapFilter &filter);

void
filterDataSet (dataSet &data, ldapFilter &filter);

#endif
