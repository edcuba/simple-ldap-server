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
    int received1 = 0;
    int msgId = 0;
};

static unsigned char
getByte (ldapContext *context)
{
    if (context->level == 1) {
        context->received1 += 1;
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
    }
    return NULL;
}

static unsigned char *
processProtocolOp (ldapContext *context)
{
    while (context->received1 < context->length1) {
        getByte (context);
    }
    return NULL;
}

static unsigned char *
processLdapMessage (ldapContext *context)
{
    // 0x02
    unsigned char data1 = receiveByte (context->client);

    // FIXME not sure what this is <0x01, 0x04>
    unsigned char data2 = receiveByte (context->client);

    // message ID FIXME this should be in <0, 2^32-1>
    context->msgId = receiveByte (context->client);

    if (data1 != MSG_ID) {
        pErrHex ("Invalid message, should be 0x02", data1);
        return ldapError (context, ERR_MSG);
    }

    if (data2 < 0x1 || data2 > 0x4) {
        pErrHex ("Invalid message, should be in <0x1, 0x4>", data2);
        return ldapError (context, ERR_MSG);
    }

    printD("Message ID: " << context->msgId);
    return processProtocolOp (context);
}

static unsigned char *
processLength (ldapContext *context)
{
    context->level += 1;

    unsigned char len = getByte (context);

    if (len == 0) {
        pErrHex ("Invalid message length", len);
        return ldapError (context, ERR_LENGTH);
    }

    // get length of the message
    if (context->level == 1) {
        context->length1 = len;
        printD("Level 1 length: " << dec << context->length1);

    } else {
        return ldapError (context, ERR_NOT_IMPLEMENTED);
    }

    return processLdapMessage (context);
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
