#ifndef LDAP_H
#define LDAP_H

#include <cstring>

// error types
#define ERR_HEAD 0
#define ERR_LENGTH 1
#define ERR_MSG 2
#define ERR_UNKNOWN_PROTOCOL 3
#define ERR_BIND_REQUEST 4
#define ERR_SEARCH_REQUEST 5

#define ERR_NOT_IMPLEMENTED -1

#define MSG_LDAP 0x30
#define MSG_ID 0x02
#define MSG_END 0xA0

#define MSG_ONE 0x01
#define MSG_BIND_REQUEST 0x60
#define MSG_PROP 0x04
#define MSG_ATTR 0x0A
#define MSG_BIND_REQUEST_AUTH 0x80
#define MSG_BIND_RESPONSE 0x61

#define RESPONSE_LEN 7

const unsigned char RESPONSE_SUCC[] = { 0xA, 0x1, 0x0, 0x4, 0x0, 0x4, 0x0 };
#define RESPONSE_SUCC_LEN 7

#define MSG_SEARCH_REQUEST 0x63

class ldapResponse
{
  public:
    ldapResponse (unsigned char *data, size_t len)
    {
        msg = data;
        length = len;
    }
    unsigned char *msg = NULL;
    size_t length = 0;
};

ldapResponse *
processMessage (int client);

#endif
