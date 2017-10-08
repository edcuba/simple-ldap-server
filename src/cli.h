#include "myldap.h"
#include <cstring>
#include <iostream>
#include <string>

#ifndef CLI_H
#define CLI_H

#define printE(x) std::cerr << x << std::endl
#define printD(x) \
    if (DEBUG)    \
    std::cerr << "D: " << x << std::endl
#define pError(x) std::cerr << "Error: " << x << " - " << strerror (errno) << std::endl

class config
{
  public:
    int port = 389;
    std::string file;
};

bool
parseCli (int argc, char const* argv[], config& c);
bool
isHelp (int argc, char const* argv[]);

#endif
