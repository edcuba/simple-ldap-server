#include "response.h"
#include "ldap.h"

using namespace std;

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
