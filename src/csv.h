#ifndef CSV_H
#define CSV_H

#include <string>
#include <vector>

using namespace std;

class entry
{
  public:
    string cn;
    string login;
    string email;
};

vector<entry> *
loadDB (const string &f);

#endif
