#ifndef SERVER_H
#define SERVER_H

#include "cli.h"
#include "ldap.h"

int
runServer (config &c);

unsigned char
receiveByte (int client);

unsigned char *
readAttr (ldapContext *context);

unsigned char
getByte (ldapContext *context);

#endif
