#include "cli.h"
#include <fstream>
#include <sstream>

using namespace std;

/**
 * Load user data from CSV
 **/
vector<entry *> *
loadDB (const string &f)
{
    ifstream data (f);

    if (!data.is_open ()) {
        printE ("Failed to open database: '" << f << "'");
        return NULL;
    }

    string line;

    vector<entry *> *dataset = new vector<entry *>;

    while (getline (data, line)) {
        stringstream ss (line);
        entry *tmp = new entry ();
        getline (ss, tmp->cn, ';');
        getline (ss, tmp->login, ';');
        getline (ss, tmp->email, ';');
        dataset->push_back (tmp);
    }

    data.close ();
    return dataset;
}
