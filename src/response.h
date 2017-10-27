#ifndef RESPONSE_H
#define RESPONSE_H

#include "result.h"
#include <string>
#include <vector>

using namespace std;

class partialList
{
  public:
    partialList (const char *t) { type = t; }
    const char *type = NULL;
    vector<string> vals;
};

class ldapSearchEntry
{
  public:
    ldapSearchEntry (string &uid);
    ~ldapSearchEntry ();
    unsigned char *objectName = NULL;
    vector<partialList> attributes;
    void addAttribute (const char *type, string &val);
};

#endif
