#include "cli.h"
#include <cstring>

using namespace std;

/**
 * Print an error with hexadecimal value
 * @param msg error message string
 * @param val numerical value to be represented as hexadecimal number
 **/
void
pErrHex (const char *msg, unsigned char val)
{
    printE (msg << " : 0x" << hex << (int) val);
}

/**
 * Parse arguments from command line
 * Supported arguments are:
 *  -p PORT
 *      server port to use
 *  -f FILE
 *      path to CSV database
 *  -h
 *      print help and exit
 **/
bool
parseCli (int argc, char const *argv[], config &c)
{
    // get port
    for (int i = 1; i < argc; ++i) {
        if (strcmp ("-p", argv[i]) == 0) {
            if (i >= argc - 1) {
                printE ("Error: invalid port specification");
                return false;
            }
            c.port = strtol (argv[i + 1], NULL, 0);
            break;
        }
    }

    // get file
    for (int i = 1; i < argc; ++i) {
        if (strcmp ("-f", argv[i]) == 0) {
            if (i >= argc - 1) {
                printE ("Error: invalid file specification");
                return false;
            }
            c.file = argv[i + 1];
            break;
        }
    }

    if (c.file.empty ()) {
        printE ("Error: no input file specified");
        return false;
    }
    return true;
}

/**
 * Print help
 **/
bool
isHelp (int argc, char const *argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp ("-h", argv[i]) == 0) {
            printE ("Usage: \n\n\tmyldap [-p port] -f file\n");
            return true;
        }
    }
    return false;
}
