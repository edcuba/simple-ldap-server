#ifndef CSV_H
#define CSV_H

#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

typedef unordered_map<string, string> entry;

vector<entry> *
loadDB (const string &f);

#endif
