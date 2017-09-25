#include <iostream>
#include <cstring>
#include <string>

using namespace std;

int port = 389;
string file;

bool DEBUG = true;

bool parseCli(int argc, char const *argv[])
{
    // get port
    for (int i = 1; i < argc; ++i) {
        if (strcmp("-p", argv[i]) == 0) {
            if (i >= argc-1) {
                cerr << "Invalid port specification" << endl;
                return false;
            }
            port = strtol(argv[i+1],NULL, 0);
            break;
        }
    }

    //get file
    for (int i = 1; i < argc; ++i) {
        if (strcmp("-f", argv[i]) == 0) {
            if (i >= argc-1) {
                cerr << "Invalid file specification" << endl;
                return false;
            }
            file = argv[i + 1];
            break;
        }
    }

    if (file.empty()) {
        cerr << "No input file specified" << endl;
        return false;
    }
    return true;
}

bool isHelp(int argc, char const *argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp("-h", argv[i]) == 0) {
            cerr << "Usage: \n\n\tmyldap [-p port] -f file\n" << endl;
            return true;
        }
    }
    return false;
}

int main(int argc, char const *argv[])
{
    if (isHelp(argc, argv)) {
        return 0;
    }
    if (!parseCli(argc, argv)) {
        return 1;
    }

    if (DEBUG) {
        cout << "Running on port: " << port << "\nInput file: '" << file << "'"<< endl;
    }
    return 0;
}
