#ifndef SERVER_H
#define SERVER_H

#include "cli.h"

int
runServer (config& c);

unsigned char
receiveByte (int client);

#endif
