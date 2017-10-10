#ifndef LDAP_H
#define LDAP_H

// error types
#define ERR_HEAD 0
#define ERR_LENGTH 1
#define ERR_MSG 2

#define ERR_NOT_IMPLEMENTED -1


#define MSG_LDAP 0x30
#define MSG_ID 0x02

unsigned char *
processMessage (int client);

#endif
