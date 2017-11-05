#include "response.h"
#include "ber.h"
#include "csv.h"
#include "dataset.h"
#include "ldap.h"
#include <cstring>
#include <string>
#include <unistd.h>

using namespace std;

/**
 * Dump partialAttributeList structure into string in required format
 **/
string
parAttrList::dump ()
{
    // dump object type
    string objType = encodeStr (type);

    // dump object value
    string objVal = encodeStr (val);

    // craft attribute sequence of length 1
    string objSeq = encodeSet (objVal);

    // craft final sequence
    string res = encodeSeq (objType + objSeq);
    return res;
}

/**
 * Dump ldapSearchEntry structure into required format
 **/
string
ldapSearchEntry::dump ()
{
    // dump objectName
    string objName = encodeStr (objectName);

    // dump partialAttributeList entries
    string attrDump;
    for (auto &e : attributes) {
        attrDump += e.dump ();
    }

    // dump attributes
    string objAttrs = encodeSeq (attrDump);

    // craft result
    return objName + objAttrs;
}

/**
 * Insert attribute into ldapSearchEntry
 **/
void
ldapSearchEntry::addAttribute (const char *type, string &val)
{
    parAttrList p (type, val);
    attributes.push_back (p);
}

/**
 * Create new ldapSearchEntry
 **/
ldapSearchEntry::ldapSearchEntry (string &uid)
{
    objectName = "uid=" + uid;
}

void
ldapContext::sendSearchEntry (entry &e)
{
    // initialize result structure with requred attributes
    string login = e["login"];
    ldapSearchEntry res (login);
    res.addAttribute ("cn", e["cn"]);
    res.addAttribute ("login", login);
    res.addAttribute ("email", e["email"]);

    // prepare response structure
    msgData.responseProtocol = PROT_SEARCH_RESULT_ENTRY;

    // create message
    ldapMessage msg (msgData, res.dump ());

    // send message
    if (!sendMessage (client, msg)) {
        return;
    }
}

/**
 * Generate response to search request
 **/
ldapMessage
ldapContext::generateSearchResponse ()
{
    dataSet data = filterData ();
    printD ("Results:");
    int i = 0;
    for (auto e : data) {
        i++;
        if (search->sizeLimit > 0 && i > search->sizeLimit) {
            break;
        }
        printD (e->operator[] ("login")
                << " : " << e->operator[] ("cn") << " <" << e->operator[] ("email") << ">");

        sendSearchEntry (*e);
    }

    // prepare response structure
    msgData.responseProtocol = PROT_SEARCH_RESULT_DONE;
    ldapResult res (RES_SUCCESS);
    return ldapMessage (msgData, res.dump ());
}

/**
 * Generate response to particular request
 * Select propriate ldapResult
 **/
ldapMessage
ldapContext::generateResponse ()
{
    ldapResult res (RES_SUCCESS);
    switch (msgData.protocol) {
        case PROT_BIND_REQUEST:
            msgData.responseProtocol = PROT_BIND_RESPONSE;
            return ldapMessage (msgData, res.dump ());
        case PROT_SEARCH_REQUEST:
            msgData.responseProtocol = PROT_SEARCH_RESULT_DONE;
            return generateSearchResponse ();
        default:
            break;
    }
    return ldapMessage (ERR_NOT_IMPLEMENTED);
}
