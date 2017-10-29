#ifndef LDAP_H
#define LDAP_H

#include <cstring>
#include <string>
#include <vector>

class ldapContext;

#include "csv.h"
#include "dataset.h"
#include "filter.h"
#include "message.h"
#include "response.h"
#include "server.h"

#define BOOL_TRUE 0xFF

#define MSG_END 0xA0

#define MSG_ATTR 0x0A
#define MSG_BIND_REQUEST_AUTH 0x80

/**
 * Object representation of search request
 **/
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
 * Represents LDAP request
 * Contains all methods used by FSM
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
    void parseFilterOrAndNot (ldapFilter &filter);
    void parseFilterSub (ldapFilter &filter);
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
    void sendSearchEntry (entry &e);
    dataSet filterData ();
};

ldapMessage
processMessage (clientData &cd);

#endif
