#include "response.h"
#include "csv.h"
#include "ldap.h"
#include <cstring>
#include <string>

using namespace std;

void
ldapSearchEntry::addAttribute (const char *type, string &val)
{
    partialList p (type);
    p.vals.push_back (val);
    attributes.push_back (p);
}

ldapSearchEntry::ldapSearchEntry (string &uid)
{
    string s ("uid=");
    s += uid;
    size_t len = s.length ();
    objectName = new unsigned char[len];
    memcpy (objectName, s.c_str (), len);
}

ldapSearchEntry::~ldapSearchEntry ()
{
    if (objectName) {
        delete[] objectName;
    }
}

void
ldapContext::sendSearchEntry (entry &e)
{
    string uid = e["login"];
    ldapSearchEntry res (uid);
    string email = e["email"];
    res.addAttribute ("email", email);
    string cn = e["cn"];
    res.addAttribute ("cn", cn);
}

/**
 * Generate response to search request
 **/
ldapMessage
ldapContext::generateSearchResponse ()
{
    vector<entry *> dataset = filterData ();
    printD ("Results:");
    for (auto e : dataset) {
        // prepare response structure
        msgData.responseProtocol = PROT_SEARCH_RESULT_ENTRY;

        sendSearchEntry (*e);

        printD (e->operator[] ("login")
                << " : " << e->operator[] ("cn") << " <" << e->operator[] ("email") << ">");
    }

    // prepare response structure
    msgData.responseProtocol = PROT_SEARCH_RESULT_DONE;
    return ldapMessage (msgData, ldapResultSuccess ());
}

/**
 * Generate response to particular request
 * Select propriate ldapResult
 **/
ldapMessage
ldapContext::generateResponse ()
{
    switch (msgData.protocol) {
        case PROT_BIND_REQUEST:
            msgData.responseProtocol = PROT_BIND_RESPONSE;
            return ldapMessage (msgData, ldapResultSuccess ());
        case PROT_SEARCH_REQUEST:
            msgData.responseProtocol = PROT_SEARCH_RESULT_DONE;
            return generateSearchResponse ();
        default:
            break;
    }
    return ldapMessage (ERR_NOT_IMPLEMENTED);
}
