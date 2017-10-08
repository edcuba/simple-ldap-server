#include "myldap.h"
#include "cli.h"
#include "server.h"
#include <iostream>
#include <string>

using namespace std;

int
main (int argc, char const* argv[])
{
    config c;

    if (isHelp (argc, argv)) {
        return 0;
    }
    if (!parseCli (argc, argv, c)) {
        return 1;
    }

    printD ("Starting on port: " << c.port);
    printD ("Input file: '" << c.file << "'");

    return runServer (c);
}
