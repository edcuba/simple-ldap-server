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
    // open the DB file
    ifstream data (f);
    if (!data.is_open ()) {
        printE ("Failed to open database: '" << f << "'");
        return NULL;
    }

    string line;

    vector<entry> *dataset = new vector<entry>;

    // parse lines
    while (getline (data, line)) {
        entry tmp;
        size_t semi1 = line.find (";");
        size_t semi2 = line.find (";", semi1 + 1);

        // take care of trailing newline
        size_t newline = 1;
        if (line.find ('\n') != string::npos || line.find ('\r') != string::npos) {
            newline = 2;
        }

        // initialize object
        tmp["cn"] = line.substr (0, semi1);
        tmp["uid"] = line.substr (semi1 + 1, semi2 - semi1 - 1);
        tmp["mail"] = line.substr (semi2 + 1, line.size () - semi2 - newline);
        dataset->push_back (tmp);
    }

    data.close ();
    return dataset;
}
