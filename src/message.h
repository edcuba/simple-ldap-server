#ifndef MESSAGE_H
#define MESSAGE_H

#include "result.h"
#include <cstring>

using namespace std;

typedef enum {
    ERR_NOT_IMPLEMENTED = -1,
    ERR_HEAD = 0,
    ERR_LENGTH = 1,
    ERR_MSG = 2,
    ERR_UNKNOWN_PROTOCOL = 3,
    ERR_BIND_REQUEST = 4,
    ERR_SEARCH_REQUEST = 5,
    ERR_FILTER = 6,
    ERR_UNBIND = 7
} ldapErrorType;

typedef enum {
    PROT_UNKNOWN = 0,
    PROT_UNBIND_REQUEST = 0x42,
    PROT_BIND_REQUEST = 0x60,
    PROT_BIND_RESPONSE = 0x61,
    PROT_SEARCH_REQUEST = 0x63,
    PROT_SEARCH_RESULT_ENTRY = 0x64,
    PROT_SEARCH_RESULT_DONE = 0x65
} ldapProtocolType;

class ldapMessageData
{
  public:
    int id = 0;
    ldapProtocolType protocol = PROT_UNKNOWN;
    ldapProtocolType responseProtocol = PROT_UNKNOWN;
};

class ldapMessage
{
  public:
    ldapMessage (const ldapMessageData &msgData, const ldapResult &result);
    ldapMessage (ldapErrorType type);
    ~ldapMessage ();
    const size_t getSize () const;
    const unsigned char *getData () const;

  protected:
    unsigned char *data;
    size_t size;
};

#endif
