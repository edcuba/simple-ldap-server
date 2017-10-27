#ifndef LDAP_H
#define LDAP_H

#include <cstring>
#include <string>
#include <vector>

class ldapContext;

#include "csv.h"
#include "filter.h"
#include "message.h"
#include "response.h"
#include "server.h"

#define BOOL_TRUE 0xFF

#define MSG_LDAP 0x30
#define MSG_ID 0x02
#define MSG_END 0xA0

#define MSG_ONE 0x01
#define MSG_PROP 0x04
#define MSG_ATTR 0x0A
#define MSG_BIND_REQUEST_AUTH 0x80

#define EXPECT(data, val, err)                                                               \
    if (data != val) {                                                                       \
        printE ("expected: 0x" << std::hex << val << ", got: 0x" << std::hex << (int) data); \
        return ldapMessage (err);                                                            \
    }

#define EXPECT_RANGE(data, from, to, err)                                                      \
    if (data < from || data > to) {                                                            \
        printE ("expected <" << from << ", " << to << ">, got: 0x" << std::hex << (int) data); \
        return ldapMessage (err);                                                              \
    }

class ldapSearch
{
  public:
    ldapFilter filter;
    vector<string> attrs;
    string baseObject;
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
    }
    int client = 0;
    int level = 0;
    int length1 = 0;
    int length2 = 0;
    int received1 = 0;
    int received2 = 0;
    ldapSearch *search = NULL;
    ldapMessageData msgData;
    ldapMessage processLength ();
    ldapMessage parseFilter ();
    string readAttr ();
    unsigned char getByte ();

  protected:
    void parseFilterEq (ldapFilter &filter);
    ldapFilter parseSubFilter ();
    vector<entry> *data;
    ldapMessage processSearchDescList ();
    ldapMessage generateResponse ();
    ldapMessage processMessageEnd ();
    ldapMessage processBindRequestAuth ();
    ldapMessage processBindRequestName ();
    ldapMessage processBindRequest ();
    ldapMessage processSearchRequest ();
    ldapMessage processProtocolOp ();
    ldapMessage processLdapMessage ();
    ldapMessage generateSearchResponse ();
    vector<entry *> filterData ();
};

ldapMessage
processMessage (clientData &cd);

#endif
