#include "cli.h"
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

class entry
{
  public:
    string name;
    string login;
    string email;
};

void
loadDB ()
{
    ifstream data ("static/isa2017-ldap.csv");

    string line;

    vector<entry *> dataset;

    while (getline (data, line)) {
        stringstream ss (line);
        entry *tmp = new entry ();
        getline (ss, tmp->name, ';');
        getline (ss, tmp->login, ';');
        getline (ss, tmp->email, ';');
        dataset.push_back (tmp);
    }

    for (auto &e : dataset) {
        printD (e->name << " " << e->login << " " << e->email);
    }

    data.close ();
}
