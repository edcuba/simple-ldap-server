#ifndef LDAP_H
#define LDAP_H

#include <cstring>
#include <vector>

class ldapContext;
class ldapResponse;

#include "filter.h"
#include "server.h"

// error types
#define ERR_HEAD 0
#define ERR_LENGTH 1
#define ERR_MSG 2
#define ERR_UNKNOWN_PROTOCOL 3
#define ERR_BIND_REQUEST 4
#define ERR_SEARCH_REQUEST 5
#define ERR_FILTER 6
#define BOOL_TRUE 0xFF

#define ERR_NOT_IMPLEMENTED -1

#define MSG_LDAP 0x30
#define MSG_ID 0x02
#define MSG_END 0xA0

#define MSG_ONE 0x01
#define MSG_PROP 0x04
#define MSG_ATTR 0x0A
#define MSG_BIND_REQUEST_AUTH 0x80

#define RESPONSE_LEN 7

const unsigned char RESPONSE_SUCC[] = { 0xA, 0x1, 0x0, 0x4, 0x0, 0x4, 0x0 };
#define RESPONSE_SUCC_LEN 7

typedef enum {
    PROT_UNKNOWN = 0,
    PROT_BIND_REQUEST = 0x60,
    PROT_BIND_RESPONSE = 0x61,
    PROT_SEARCH_REQUEST = 0x63
} protocolType;

#define EXPECT(data, val)                                                                    \
    if (data != val) {                                                                       \
        printE ("expected: 0x" << std::hex << val << ", got: 0x" << std::hex << (int) data); \
        return ldapError (val);                                                              \
    }

#define EXPECT_RANGE(data, from, to, err)                                                      \
    if (data < from || data > to) {                                                            \
        printE ("expected <" << from << ", " << to << ">, got: 0x" << std::hex << (int) data); \
        return ldapError (err);                                                                \
    }

/**
 * LDAP response structure
 * represents data being send back to client and their length
 **/
class ldapResponse
{
  public:
    ldapResponse (unsigned char *data, size_t len)
    {
        msg = data;
        length = len;
    }
    ~ldapResponse ()
    {
        if (msg) {
            delete msg;
        }
    }
    unsigned char *msg = NULL;
    size_t length = 0;
};

class ldapSearch
{
  public:
    ~ldapSearch ()
    {
        if (baseObject) {
            delete baseObject;
        }
        for (auto &e : attrs) {
            delete e;
        }
    }
    ldapFilter filter;
    std::vector<unsigned char *> attrs;
    unsigned char *baseObject = NULL;
    unsigned char scope = 0;
    unsigned char derefAliases = 0;
    int sizeLimit = 0;
    int timeLimit = 0;
    bool typesonly = false;
};

/**
 * LDAP context structure
 * represents LDAP request
 **/
class ldapContext
{
  public:
    ldapContext (clientData &cd)
    {
        client = cd.client ();
        data = cd.data ();
    }
    ~ldapContext ()
    {
        if (search) {
            delete search;
        }
        if (result) {
            delete result;
        }
    }
    int client = 0;
    int level = 0;
    int length1 = 0;
    int length2 = 0;
    int received1 = 0;
    int received2 = 0;
    int msgId = 0;
    protocolType protocol = PROT_UNKNOWN;
    unsigned char *result = NULL;
    int resultlen = 0;
    protocolType responseProtocol = PROT_UNKNOWN;
    ldapSearch *search = NULL;

    ldapResponse processLength ();
    ldapResponse parseFilter ();
    unsigned char *readAttr ();
    unsigned char getByte ();
    ldapResponse ldapError (int type);

  protected:
    void parseFilterEq (ldapFilter &filter);
    ldapFilter parseSubFilter ();
    vector<entry> *data;
    ldapResponse processSearchDescList ();
    ldapResponse generateLdapMessage ();
    ldapResponse generateResultSuccess ();
    ldapResponse generateResponse ();
    ldapResponse processMessageEnd ();
    ldapResponse processBindRequestAuth ();
    ldapResponse processBindRequestName ();
    ldapResponse processBindRequest ();
    ldapResponse processSearchRequest ();
    ldapResponse processProtocolOp ();
    ldapResponse processLdapMessage ();
    ldapResponse generateSearchResponse ();
};

ldapResponse
processMessage (clientData &cd);

#endif
