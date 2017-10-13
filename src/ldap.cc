#include "ldap.h"
#include "cli.h"
#include "server.h"

using namespace std;

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
};

unsigned char *
processLength (ldapContext *context);

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

static void
pErrHex (const char *msg, unsigned char val)
{
    printE (msg << ": 0x" << hex << val);
}

static unsigned char *
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

static unsigned char *
generateResponse (ldapContext *context)
{
    return NULL; // TODO
}

static unsigned char *
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

static unsigned char *
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

static unsigned char *
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

static unsigned char *
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

static unsigned char *
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

static unsigned char *
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

unsigned char *
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
unsigned char *
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
