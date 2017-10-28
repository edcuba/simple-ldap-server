#ifndef RESPONSE_H
#define RESPONSE_H

#include "result.h"
#include <string>
#include <vector>

using namespace std;

class parAttrList
{
  public:
    parAttrList (const char *t, string &v)
    {
        type = t;
        val = v;
    }
    string type;
    string val;
    string dump ();
};

class ldapSearchEntry
{
  public:
    ldapSearchEntry (string &uid);
    string objectName;
    vector<parAttrList> attributes;
    void addAttribute (const char *type, string &val);
    string dump ();
};

#endif
