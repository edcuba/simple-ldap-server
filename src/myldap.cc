#include "myldap.h"
#include "cli.h"
#include "csv.h"
#include "server.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

int
main (int argc, char const *argv[])
{
    // load configuration
    config c;

    if (isHelp (argc, argv)) {
        return 0;
    }
    if (!parseCli (argc, argv, c)) {
        return 1;
    }

    printD ("Input file: '" << c.file << "'");

    printD ("Loading database");
    c.data = loadDB (c.file);

    if (c.data == NULL) {
        return 2;
    }

    printD ("Starting on port: " << c.port);

    // start server loop
    return runServer (c);
}
