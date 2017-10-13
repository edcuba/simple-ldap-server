#ifndef LDAP_H
#define LDAP_H

// error types
#define ERR_HEAD 0
#define ERR_LENGTH 1
#define ERR_MSG 2
#define ERR_UNKNOWN_PROTOCOL 3
#define ERR_BIND_REQUEST 4

#define ERR_NOT_IMPLEMENTED -1


#define MSG_LDAP 0x30
#define MSG_ID 0x02
#define MSG_END 0xA0

#define MSG_BIND_REQUEST 0x60
#define MSG_BIND_REQUEST_NAME 0x04
#define MSG_BIND_REQUEST_AUTH 0x80



#define MSG_SEARCH_REQUEST 0x63

unsigned char *
processMessage (int client);

#endif
