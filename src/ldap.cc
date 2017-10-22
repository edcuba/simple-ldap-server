#include "ldap.h"
#include "cli.h"
#include "server.h"

using namespace std;

/**
 * Generate response with error code
 * @param type error type code
 **/
ldapResponse
ldapContext::ldapError (int type)
{
    switch (type) {
        case ERR_NOT_IMPLEMENTED:
            printE ("Feature not implemented");
            break;
        case ERR_UNKNOWN_PROTOCOL:
            break;
    }
    return ldapResponse (NULL, 0);
}

/**
 * Wrap the ldapResult into ldapMessage
 **/
ldapResponse
ldapContext::generateLdapMessage ()
{
    size_t length = RESPONSE_LEN + resultlen;

    // initialize message header
    unsigned char *protocolOp = new unsigned char[length];
    protocolOp[0] = MSG_LDAP;
    protocolOp[1] = length - 2; // except Ox3O LL
    protocolOp[2] = MSG_ID;
    protocolOp[3] = MSG_ONE;
    protocolOp[4] = msgId;
    protocolOp[5] = responseProtocol;
    protocolOp[6] = resultlen;

    // add rest of the message
    memcpy (protocolOp + RESPONSE_LEN, result, resultlen);

    if (DEBUG) {
        printD ("Response message");
        for (unsigned i = 0; i < length; ++i) {
            cerr << " 0x" << hex << (int) protocolOp[i];
        }
        cerr << endl;
    }

    return ldapResponse (protocolOp, length);
}

/**
 * Generate ldapResult of type success (0)
 **/
ldapResponse
ldapContext::generateResultSuccess ()
{
    result = new unsigned char[RESPONSE_SUCC_LEN];
    memcpy (result, RESPONSE_SUCC, RESPONSE_LEN);
    resultlen = RESPONSE_SUCC_LEN;
    return generateLdapMessage ();
}

/**
 * Generate response to search request
 **/
ldapResponse
ldapContext::generateSearchResponse ()
{
    return ldapError (ERR_NOT_IMPLEMENTED);
}

/**
 * Generate response to particular request
 * Select propriate ldapResult
 **/
ldapResponse
ldapContext::generateResponse ()
{
    switch (protocol) {
        case PROT_BIND_REQUEST:
            responseProtocol = PROT_BIND_RESPONSE;
            return generateResultSuccess ();
        case PROT_SEARCH_REQUEST:
            return generateSearchResponse ();
        default:
            break;
    }
    return ldapError (ERR_NOT_IMPLEMENTED);
}

/**
 * Process end of the message
 **/
ldapResponse
ldapContext::processMessageEnd ()
{
    unsigned char data = 0; // FIXME support 0xA0

    if (data == 0 || data == MSG_END) {
        printD ("Message correct");
        return generateResponse ();
    }
    printE ("Message corrupt!");
    return ldapError (ERR_MSG);
}

/**
 * Process bindRequest authentification
 **/
ldapResponse
ldapContext::processBindRequestAuth ()
{
    unsigned char data = getByte ();
    EXPECT (data, MSG_BIND_REQUEST_AUTH);

    // simple auth length
    unsigned char *name = readAttr ();

    if (name) {
        delete name;
    }

    return processMessageEnd ();
}

/**
 * Process bindRequest name
 **/
ldapResponse
ldapContext::processBindRequestName ()
{
    unsigned char data = getByte ();
    EXPECT (data, MSG_PROP);

    unsigned char *name = readAttr ();

    if (name) {
        delete name;
    }

    return processBindRequestAuth ();
}

/**
 * Process bindRequest header
 **/
ldapResponse
ldapContext::processBindRequest ()
{
    printD ("Protocol: bindRequest");

    unsigned char data = getByte ();
    EXPECT (data, MSG_ID);

    data = getByte ();
    EXPECT (data, MSG_ONE);

    data = getByte ();
    EXPECT_RANGE (data, 1, 127, ERR_BIND_REQUEST);

    return processBindRequestName ();
}

/**
 * Process searchRequest AttributeDescList property
 **/
ldapResponse
ldapContext::processSearchDescList ()
{
    printD ("Parsing description list");
    unsigned char data = getByte ();
    EXPECT (data, MSG_LDAP);

    unsigned char len = getByte ();
    int limit = received1 + len;

    while (received1 < limit) {
        data = getByte ();
        EXPECT (data, MSG_PROP);
        search->attrs.push_back (readAttr ());
    }

    return processMessageEnd ();
}

/**
 * Process searchRequest header
 **/
ldapResponse
ldapContext::processSearchRequest ()
{
    printD ("Protocol: searchRequest");

    search = new ldapSearch ();

    // parse baseObject
    unsigned char data = getByte ();
    EXPECT (data, MSG_PROP);

    printD ("baseObject:");
    search->baseObject = readAttr ();

    // parse scope
    data = getByte ();
    EXPECT (data, MSG_ATTR);
    data = getByte ();
    EXPECT (data, MSG_ONE);
    search->scope = getByte ();

    printD ("scope:");
    EXPECT_RANGE (search->scope, 0, 2, ERR_SEARCH_REQUEST);

    // parse derefAliases
    data = getByte ();
    EXPECT (data, MSG_ATTR);
    data = getByte ();
    EXPECT (data, MSG_ONE);
    search->derefAliases = getByte ();

    printD ("derefAliases:");
    EXPECT_RANGE (search->derefAliases, 0, 3, ERR_SEARCH_REQUEST);

    // parse sizeLimit
    data = getByte ();
    EXPECT (data, MSG_ID);
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("sizeLimit:");
    search->sizeLimit = getByte ();

    // parse timeLimit
    data = getByte ();
    EXPECT (data, MSG_ID);
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("timeLimit:");
    search->timeLimit = getByte ();

    // parse typesonly
    data = getByte ();
    EXPECT (data, MSG_ONE);
    data = getByte ();
    EXPECT (data, MSG_ONE);
    printD ("typesonly:");
    search->typesonly = (getByte () == BOOL_TRUE) ? true : false;

    return parseFilter ();
}

/**
 * Parse protocol type
 **/
ldapResponse
ldapContext::processProtocolOp ()
{
    unsigned char protocolOp = getByte ();

    switch (protocolOp) {
        case PROT_BIND_REQUEST:
            protocol = PROT_BIND_REQUEST;
            return processLength ();
        case PROT_SEARCH_REQUEST:
            protocol = PROT_SEARCH_REQUEST;
            return processLength ();
    }

    pErrHex ("Unknown protocol", protocolOp);
    return ldapError (ERR_UNKNOWN_PROTOCOL);
}

/**
 * Process ldapMessage header
 **/
ldapResponse
ldapContext::processLdapMessage ()
{
    // 0x02
    unsigned char data = getByte ();
    EXPECT (data, MSG_ID);

    // message ID FIXME this should be in <0, 2^32-1>
    msgId = getByte ();

    // FIXME not sure what this is <0x01, 0x04>
    data = getByte ();
    EXPECT_RANGE (data, 1, 4, ERR_MSG);

    printD ("Message ID: " << msgId);
    return processProtocolOp ();
}

/**
 * Parse and process length of the next section in the message
 **/
ldapResponse
ldapContext::processLength ()
{
    level += 1;
    unsigned char len = getByte ();

    if (len == 0) {
        pErrHex ("Invalid message length", len);
        return ldapError (ERR_LENGTH);
    }

    switch (level) {
        case 1:
            length1 = len;
            printD ("Level 1 length: " << dec << length1);
            return processLdapMessage ();
        case 2:
            length2 = len;
            printD ("Level 2 length: " << dec << length2);
            switch (protocol) {
                case PROT_BIND_REQUEST:
                    return processBindRequest ();
                case PROT_SEARCH_REQUEST:
                    return processSearchRequest ();
                default:
                    break;
            }
            break;
    }
    return ldapError (ERR_NOT_IMPLEMENTED);
}

/**
 * Process message from client and generate response
 * @return byte response
 **/
ldapResponse
processMessage (clientData &cd)
{
    // initialize context for communication
    ldapContext context (cd);

    // read first two bytes expect LdapMessage - 0x30 and length of L1 message
    int type = context.getByte ();

    if (type != MSG_LDAP) {
        printE ("Invalid LDAP header: Ox" << hex << type);
        return context.ldapError (MSG_LDAP);
    }

    return context.processLength ();
}
