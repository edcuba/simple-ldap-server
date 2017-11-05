#include "ldap.h"
#include "cli.h"
#include "server.h"

using namespace std;

/**
 * Process end of the message
 **/
ldapMessage
ldapContext::processMessageEnd ()
{
    printD ("Message correct");
    return generateResponse ();
}

/**
 * Process bindRequest authentification
 **/
ldapMessage
ldapContext::processBindRequestAuth ()
{
    unsigned char data = getByte ();
    EXPECT (data, MSG_BIND_REQUEST_AUTH, ERR_BIND_REQUEST);

    // simple auth length
    string name = readAttr ();
    printD ("Auth name: " << name);

    return processMessageEnd ();
}

/**
 * Process bindRequest name
 **/
ldapMessage
ldapContext::processBindRequestName ()
{
    unsigned char data = getByte ();
    EXPECT (data, 0x04, ERR_BIND_REQUEST);

    string name = readAttr ();

    printD ("Bind name: " << name);

    return processBindRequestAuth ();
}

/**
 * Process bindRequest header
 **/
ldapMessage
ldapContext::processBindRequest ()
{
    printD ("Protocol: bindRequest");

    int version = readInt ();

    printD ("Version: " << dec << version);

    if (version > 127) {
        return ldapMessage (ERR_BIND_REQUEST);
    }

    return processBindRequestName ();
}

/**
 * Process searchRequest AttributeDescList property
 **/
ldapMessage
ldapContext::processSearchDescList ()
{
    printD ("Parsing description list");
    unsigned char data = getByte ();
    EXPECT (data, 0x30, ERR_SEARCH_REQUEST);

    size_t len = readLength ();
    size_t limit = received + len;

    while (received < limit) {
        data = getByte ();
        EXPECT (data, 0x04, ERR_SEARCH_REQUEST);
        search->attrs.push_back (readAttr ());
    }

    return processMessageEnd ();
}

/**
 * Process searchRequest header
 **/
ldapMessage
ldapContext::processSearchRequest ()
{
    printD ("Protocol: searchRequest");

    search = new ldapSearch ();

    // parse baseObject
    unsigned char data = getByte ();
    EXPECT (data, 0x04, ERR_SEARCH_REQUEST);

    printD ("baseObject:");
    search->baseObject = readAttr ();

    // parse scope
    data = getByte ();
    EXPECT (data, MSG_ATTR, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, 0x01, ERR_SEARCH_REQUEST);
    search->scope = getByte ();

    printD ("scope:");
    EXPECT_RANGE (search->scope, 0, 2, ERR_SEARCH_REQUEST);

    // parse derefAliases
    data = getByte ();
    EXPECT (data, MSG_ATTR, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, 0x01, ERR_SEARCH_REQUEST);
    search->derefAliases = getByte ();

    printD ("derefAliases:");
    EXPECT_RANGE (search->derefAliases, 0, 3, ERR_SEARCH_REQUEST);

    // parse sizeLimit
    search->sizeLimit = readInt ();
    printD ("sizeLimit:" << search->sizeLimit);

    // parse timeLimit
    search->timeLimit = readInt ();
    printD ("timeLimit:" << search->timeLimit);

    // parse typesonly
    data = getByte ();
    EXPECT (data, 0x01, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, 0x01, ERR_SEARCH_REQUEST);
    printD ("typesonly:");
    search->typesonly = (getByte () == BOOL_TRUE) ? true : false;

    return parseFilter ();
}

/**
 * Parse protocol type
 **/
ldapMessage
ldapContext::processProtocolOp ()
{
    unsigned char protocolOp = getByte ();

    switch (protocolOp) {
        case PROT_BIND_REQUEST:
            msgData.protocol = PROT_BIND_REQUEST;
            return processLength ();
        case PROT_SEARCH_REQUEST:
            msgData.protocol = PROT_SEARCH_REQUEST;
            return processLength ();
        case PROT_UNBIND_REQUEST:
            // this flag is just happily ignored
            return ldapMessage (ERR_UNBIND);
    }

    pErrHex ("Unknown protocol", protocolOp);
    return ldapMessage (ERR_UNKNOWN_PROTOCOL);
}

/**
 * Process ldapMessage header
 **/
ldapMessage
ldapContext::processLdapMessage ()
{
    msgData.id = readInt ();
    printD ("Message ID: " << msgData.id);
    return processProtocolOp ();
}

/**
 * Parse and process length of the next section in the message
 **/
ldapMessage
ldapContext::processLength ()
{
    level += 1;
    size_t len = readLength ();

    if (len == 0) {
        pErrHex ("Invalid message length", len);
        return ldapMessage (ERR_LENGTH);
    }

    switch (level) {
        case 1:
            printD ("Level 1 length: " << dec << len);
            return processLdapMessage ();
        case 2:
            printD ("Level 2 length: " << dec << len);
            switch (msgData.protocol) {
                case PROT_BIND_REQUEST:
                    return processBindRequest ();
                case PROT_SEARCH_REQUEST:
                    return processSearchRequest ();
                default:
                    break;
            }
            break;
    }
    return ldapMessage (ERR_NOT_IMPLEMENTED);
}

/**
 * Process message from client and generate response
 * @return byte response
 **/
ldapMessage
processMessage (clientData &cd)
{
    // initialize context for communication
    ldapContext context (cd);

    // read first two bytes expect LdapMessage - 0x30 and length of L1 message
    int type = context.getByte ();

    if (type != 0x30) {
        printE ("Invalid LDAP header: Ox" << hex << type);
        return ldapMessage (ERR_MSG);
    }

    return context.processLength ();
}
