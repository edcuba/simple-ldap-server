#include "ldap.h"
#include "cli.h"
#include "server.h"

using namespace std;

/**
 * LDAP context structure
 * represents LDAP request
 **/
class ldapContext
{
  public:
    ldapContext (int _client) { client = _client; }
    int client = 0;
    int level = 0;
    int length1 = 0;
    int length2 = 0;
    int received1 = 0;
    int received2 = 0;
    int msgId = 0;
    int protocol = 0;
    unsigned char *result = NULL;
    int resultlen = 0;
    int responseProtocol = 0;
};

ldapResponse *
processLength (ldapContext *context);

/**
 * Read single byte from socket descriptor and count in to actual level
 * @param context ldap message context
 **/
static unsigned char
getByte (ldapContext *context)
{
    switch (context->level) {
        case 1:
            context->received1 += 1;
            break;
        case 2:
            context->received2 += 1;
            break;
    }

    return receiveByte (context->client);
}

/**
 * Print an error with hexadecimal value
 * @param msg error message string
 * @param val numerical value to be represented as hexadecimal number
 **/
static void
pErrHex (const char *msg, unsigned char val)
{
    printE (msg << ": 0x" << hex << (int) val);
}

/**
 * Generate response with error code
 * @param context ldap message context
 * @param type error type code
 **/
static ldapResponse *
ldapError (ldapContext *context, int type)
{
    free (context);
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
    protocolOp[3] = 0x01;
    protocolOp[4] = context->msgId;
    protocolOp[5] = context->responseProtocol;
    protocolOp[6] = context->resultlen;

    // add rest of the message
    memcpy (protocolOp + RESPONSE_LEN, context->result, context->resultlen);

    // free the context
    free (context);

    if (DEBUG) {
        printD ("Response message");
        for (int i = 0; i < length; ++i) {
            cerr << " 0x" << hex << (int) protocolOp[i];
        }
        cerr << endl;
    }

    return new ldapResponse(protocolOp, length);
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
            generateResultSuccess (context);
    }
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

    if (data != MSG_BIND_REQUEST_AUTH) {
        pErrHex ("Invalid bindRequest auth, should start with 0x80", data);
        return ldapError (context, ERR_BIND_REQUEST);
    }

    // simple auth length
    unsigned char len = getByte (context);

    char *name = NULL;

    if (len) {
        return ldapError (context, ERR_NOT_IMPLEMENTED);
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

    if (data != MSG_BIND_REQUEST_NAME) {
        pErrHex ("Invalid bindRequest name, should start with 0x04", data);
        return ldapError (context, ERR_BIND_REQUEST);
    }

    // name length
    unsigned char len = getByte (context);

    if (len) {
        return ldapError (context, ERR_NOT_IMPLEMENTED);
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

    if (data != MSG_ID) {
        pErrHex ("Invalid bindRequest sequence, should be 0x02", data);
        return ldapError (context, ERR_BIND_REQUEST);
    }

    data = getByte (context);

    if (data != 0x01) {
        pErrHex ("Invalid bindRequest sequence, should be 0x01", data);
        return ldapError (context, ERR_BIND_REQUEST);
    }

    data = getByte (context);

    if (data < 1 || data > 127) {
        pErrHex ("Invalid bindRequest version, should be in <1, 127>", data);
        return ldapError (context, ERR_BIND_REQUEST);
    }

    return processBindRequestName (context);
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
    unsigned char data1 = getByte (context);

    // FIXME not sure what this is <0x01, 0x04>
    unsigned char data2 = getByte (context);

    // message ID FIXME this should be in <0, 2^32-1>
    context->msgId = getByte (context);

    if (data1 != MSG_ID) {
        pErrHex ("Invalid message, should be 0x02", data1);
        return ldapError (context, ERR_MSG);
    }

    if (data2 < 0x1 || data2 > 0x4) {
        pErrHex ("Invalid message, should be in <0x1, 0x4>", data2);
        return ldapError (context, ERR_MSG);
    }

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

    if (type != MSG_LDAP) {
        pErrHex ("Invalid message header", type);
        return ldapError (context, ERR_HEAD);
    }

    return processLength (context);
}
