#include "ldap.h"
#include "cli.h"
#include "server.h"

using namespace std;

/**
 * Generate response with error code
 * @param context ldap message context
 * @param type error type code
 **/
ldapResponse *
ldapError (ldapContext *context, int type)
{
    delete context;
    switch (type) {
        case ERR_NOT_IMPLEMENTED:
            printE ("Feature not implemented");
            break;
        case ERR_UNKNOWN_PROTOCOL:
            break;
    }
    return NULL;
}

/**
 * Wrap the ldapResult into ldapMessage
 * @param context ldap message context
 **/
static ldapResponse *
generateLdapMessage (ldapContext *context)
{
    size_t length = RESPONSE_LEN + context->resultlen;

    // initialize message header
    unsigned char *protocolOp = new unsigned char[length];
    protocolOp[0] = MSG_LDAP;
    protocolOp[1] = length - 2; // except Ox3O LL
    protocolOp[2] = MSG_ID;
    protocolOp[3] = MSG_ONE;
    protocolOp[4] = context->msgId;
    protocolOp[5] = context->responseProtocol;
    protocolOp[6] = context->resultlen;

    // add rest of the message
    memcpy (protocolOp + RESPONSE_LEN, context->result, context->resultlen);

    // free the context
    delete context;

    if (DEBUG) {
        printD ("Response message");
        for (unsigned i = 0; i < length; ++i) {
            cerr << " 0x" << hex << (int) protocolOp[i];
        }
        cerr << endl;
    }

    return new ldapResponse (protocolOp, length);
}

/**
 * Generate ldapResult of type success (0)
 * @param context ldap message context
 **/
static ldapResponse *
generateResultSuccess (ldapContext *context)
{
    context->result = new unsigned char[RESPONSE_SUCC_LEN];
    memcpy (context->result, RESPONSE_SUCC, RESPONSE_LEN);
    context->resultlen = RESPONSE_SUCC_LEN;
    return generateLdapMessage (context);
}

/**
 * Generate response to particular request
 * Select propriate ldapResult
 * @param context ldap message context
 **/
static ldapResponse *
generateResponse (ldapContext *context)
{
    switch (context->protocol) {
        case MSG_BIND_REQUEST:
            context->responseProtocol = MSG_BIND_RESPONSE;
            return generateResultSuccess (context);
    }
    return ldapError (context, ERR_NOT_IMPLEMENTED);
}

/**
 * Process end of the message
 * @param context ldap message context
 **/
static ldapResponse *
processMessageEnd (ldapContext *context)
{
    unsigned char data = 0; // FIXME support 0xA0

    if (data == 0 || data == MSG_END) {
        printD ("Message correct");
        return generateResponse (context);
    }
    printE ("Message corrupt!");
    return ldapError (context, ERR_MSG);
}

/**
 * Process bindRequest authentification
 * @param context ldap message context
 **/
static ldapResponse *
processBindRequestAuth (ldapContext *context)
{
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_BIND_REQUEST_AUTH);

    // simple auth length
    unsigned char *name = readAttr (context);

    if (name) {
        delete name;
    }

    return processMessageEnd (context);
}

/**
 * Process bindRequest name
 * @param context ldap message context
 **/
static ldapResponse *
processBindRequestName (ldapContext *context)
{
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_PROP);

    unsigned char *name = readAttr (context);

    if (name) {
        delete name;
    }

    return processBindRequestAuth (context);
}

/**
 * Process bindRequest header
 * @param context ldap message context
 **/
static ldapResponse *
processBindRequest (ldapContext *context)
{
    printD ("Protocol: bindRequest");

    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_ID);

    data = getByte (context);
    EXPECT (context, data, MSG_ONE);

    data = getByte (context);
    EXPECT_RANGE (context, data, 1, 127, ERR_BIND_REQUEST);

    return processBindRequestName (context);
}

/**
 * Process searchRequest AttributeDescList property
 * @param context ldap message context
 **/
ldapResponse *
processSearchDescList (ldapContext *context)
{
    printD ("Parsing description list");
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_LDAP);

    unsigned char len = getByte (context);
    int limit = context->received1 + len;

    while (context->received1 < limit) {
        data = getByte (context);
        EXPECT (context, data, MSG_PROP);
        context->search->attrs.push_back (readAttr (context));
    }

    return processMessageEnd (context);
}

/**
 * Process searchRequest header
 * @param context ldap message context
 **/
static ldapResponse *
processSearchRequest (ldapContext *context)
{
    printD ("Protocol: searchRequest");

    ldapSearch *search = new ldapSearch ();

    context->search = search;

    // parse baseObject
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_PROP);

    printD ("baseObject:");
    search->baseObject = readAttr (context);

    // parse scope
    data = getByte (context);
    EXPECT (context, data, MSG_ATTR);
    data = getByte (context);
    EXPECT (context, data, MSG_ONE);
    search->scope = getByte (context);

    printD ("scope:");
    EXPECT_RANGE (context, search->scope, 0, 2, ERR_SEARCH_REQUEST);

    // parse derefAliases
    data = getByte (context);
    EXPECT (context, data, MSG_ATTR);
    data = getByte (context);
    EXPECT (context, data, MSG_ONE);
    search->derefAliases = getByte (context);

    printD ("derefAliases:");
    EXPECT_RANGE (context, search->derefAliases, 0, 3, ERR_SEARCH_REQUEST);

    // parse sizeLimit
    data = getByte (context);
    EXPECT (context, data, MSG_ID);
    data = getByte (context);
    EXPECT_RANGE (context, data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("sizeLimit:");
    search->sizeLimit = getByte (context);

    // parse timeLimit
    data = getByte (context);
    EXPECT (context, data, MSG_ID);
    data = getByte (context);
    EXPECT_RANGE (context, data, 1, 4, ERR_SEARCH_REQUEST);
    printD ("timeLimit:");
    search->timeLimit = getByte (context);

    // parse typesonly
    data = getByte (context);
    EXPECT (context, data, MSG_ONE);
    data = getByte (context);
    EXPECT (context, data, MSG_ONE);
    printD ("typesonly:");
    search->typesonly = (getByte (context) == BOOL_TRUE) ? true : false;

    return parseFilter (context);
}

/**
 * Parse protocol type
 * @param context ldap message context
 **/
static ldapResponse *
processProtocolOp (ldapContext *context)
{
    unsigned char protocolOp = getByte (context);

    switch (protocolOp) {
        case MSG_BIND_REQUEST:
        case MSG_SEARCH_REQUEST:
            context->protocol = protocolOp;
            return processLength (context);
    }

    pErrHex ("Unknown protocol", protocolOp);
    return ldapError (context, ERR_UNKNOWN_PROTOCOL);
}

/**
 * Process ldapMessage header
 * @param context ldap message context
 **/
static ldapResponse *
processLdapMessage (ldapContext *context)
{
    // 0x02
    unsigned char data = getByte (context);
    EXPECT (context, data, MSG_ID);

    // message ID FIXME this should be in <0, 2^32-1>
    context->msgId = getByte (context);

    // FIXME not sure what this is <0x01, 0x04>
    data = getByte (context);
    EXPECT_RANGE (context, data, 1, 4, ERR_MSG);

    printD ("Message ID: " << context->msgId);
    return processProtocolOp (context);
}

/**
 * Parse and process length of the next section in the message
 * @param context ldap message context
 **/
ldapResponse *
processLength (ldapContext *context)
{
    context->level += 1;
    unsigned char len = getByte (context);

    if (len == 0) {
        pErrHex ("Invalid message length", len);
        return ldapError (context, ERR_LENGTH);
    }

    switch (context->level) {
        case 1:
            context->length1 = len;
            printD ("Level 1 length: " << dec << context->length1);
            return processLdapMessage (context);
        case 2:
            context->length2 = len;
            printD ("Level 2 length: " << dec << context->length2);
            switch (context->protocol) {
                case MSG_BIND_REQUEST:
                    return processBindRequest (context);
                case MSG_SEARCH_REQUEST:
                    return processSearchRequest (context);
            }
            break;
    }
    return ldapError (context, ERR_NOT_IMPLEMENTED);
}

/**
 * Process message from client and generate response
 * @param client socket descriptor
 * @return byte response
 **/
ldapResponse *
processMessage (int client)
{
    // initialize context for communication
    ldapContext *context = new ldapContext (client);

    // read first two bytes expect LdapMessage - 0x30 and length of L1 message
    int type = getByte (context);

    EXPECT (context, type, MSG_LDAP);

    return processLength (context);
}
