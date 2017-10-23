#include "cli.h"
#include <fstream>
#include <sstream>

using namespace std;

/**
 * Load user data from CSV
 **/
vector<entry> *
loadDB (const string &f)
{
    ifstream data (f);

    if (!data.is_open ()) {
        printE ("Failed to open database: '" << f << "'");
        return NULL;
    }

    string line;

    vector<entry> *dataset = new vector<entry>;

    while (getline (data, line)) {
        entry tmp;
        size_t semi1 = line.find (";");
        size_t semi2 = line.find (";", semi1 + 1);
        tmp["cn"] = line.substr (0, semi1);
        tmp["login"] = line.substr (semi1 + 1, semi2 - semi1 - 1);
        tmp["email"] = line.substr (semi2 + 1, line.size () - semi2 - 1);
        dataset->push_back (tmp);
    }

    data.close ();
    return dataset;
}
