#include "response.h"
#include "csv.h"
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
    string objType;
    objType += (char) 0x04;
    objType += (char) type.size ();
    objType += type;

    // dump object value
    string objVal;
    objVal += (char) 0x31;
    objVal += (char) val.size ();
    objVal += val;

    // craft final sequence
    string res;
    res += (char) 0x30;
    res += (char) (objType.size () + objVal.size ());
    res += objType;
    res += objVal;
    return res;
}

/**
 * Dump ldapSearchEntry structure into required format
 **/
string
ldapSearchEntry::dump ()
{
    // dump objectName
    string objName;
    objName += (char) 0x04;
    objName += (char) objectName.size ();
    objName += objectName;

    // dump partialAttributeList entries
    string attrDump;
    for (auto &e : attributes) {
        attrDump += e.dump ();
    }

    // dump attributes
    string objAttrs;
    objAttrs += (char) 0x30;
    objAttrs += (char) attrDump.size ();
    objAttrs += attrDump;

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
    ldapSearchEntry res (e["login"]);
    res.addAttribute ("email", e["email"]);
    res.addAttribute ("cn", e["cn"]);

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
    vector<entry *> dataset = filterData ();
    printD ("Results:");
    for (auto e : dataset) {
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
