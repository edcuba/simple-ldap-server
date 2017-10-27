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
    unsigned char data = 0; // FIXME support 0xA0

    if (data == 0 || data == MSG_END) {
        printD ("Message correct");
        return generateResponse ();
    }
    printE ("Message corrupt!");
    return ldapMessage (ERR_MSG);
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
    EXPECT (data, MSG_PROP, ERR_BIND_REQUEST);

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

    unsigned char data = getByte ();
    EXPECT (data, MSG_ID, ERR_BIND_REQUEST);

    data = getByte ();
    EXPECT (data, MSG_ONE, ERR_BIND_REQUEST);

    data = getByte ();
    EXPECT_RANGE (data, 1, 127, ERR_BIND_REQUEST);

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
    EXPECT (data, MSG_LDAP, ERR_SEARCH_REQUEST);

    unsigned char len = getByte ();
    int limit = received1 + len;

    while (received1 < limit) {
        data = getByte ();
        EXPECT (data, MSG_PROP, ERR_SEARCH_REQUEST);
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
    EXPECT (data, MSG_PROP, ERR_SEARCH_REQUEST);

    printD ("baseObject:");
    search->baseObject = readAttr ();

    // parse scope
    data = getByte ();
    EXPECT (data, MSG_ATTR, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, MSG_ONE, ERR_SEARCH_REQUEST);
    search->scope = getByte ();

    printD ("scope:");
    EXPECT_RANGE (search->scope, 0, 2, ERR_SEARCH_REQUEST);

    // parse derefAliases
    data = getByte ();
    EXPECT (data, MSG_ATTR, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, MSG_ONE, ERR_SEARCH_REQUEST);
    search->derefAliases = getByte ();

    printD ("derefAliases:");
    EXPECT_RANGE (search->derefAliases, 0, 3, ERR_SEARCH_REQUEST);

    // parse sizeLimit
    data = getByte ();
    EXPECT (data, MSG_ID, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("sizeLimit:");
    search->sizeLimit = getByte ();

    // parse timeLimit
    data = getByte ();
    EXPECT (data, MSG_ID, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("timeLimit:");
    search->timeLimit = getByte ();

    // parse typesonly
    data = getByte ();
    EXPECT (data, MSG_ONE, ERR_SEARCH_REQUEST);
    data = getByte ();
    EXPECT (data, MSG_ONE, ERR_SEARCH_REQUEST);
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
    // 0x02
    unsigned char data = getByte ();
    EXPECT (data, MSG_ID, ERR_MSG);

    // FIXME not sure what this is <0x01, 0x04>
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_MSG);

    // message ID FIXME this should be in <0, 2^32-1>
    msgData.id = getByte ();

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
    unsigned char len = getByte ();

    if (len == 0) {
        pErrHex ("Invalid message length", len);
        return ldapMessage (ERR_LENGTH);
    }

    switch (level) {
        case 1:
            length1 = len;
            printD ("Level 1 length: " << dec << length1);
            return processLdapMessage ();
        case 2:
            length2 = len;
            printD ("Level 2 length: " << dec << length2);
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

    if (type != MSG_LDAP) {
        printE ("Invalid LDAP header: Ox" << hex << type);
        return ldapMessage (ERR_MSG);
    }

    return context.processLength ();
}
