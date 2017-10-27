#include "message.h"
#include "ldap.h"

using namespace std;

/**
 * Result message contructor
 **/
ldapMessage::ldapMessage (const ldapMessageData &msgData, const ldapResult &result)
{
    // extract result data
    size_t resSize = result.getSize ();
    const char *resData = result.getData ();
    printD ("Result size: 0x" << hex << resSize);

    // data length + message header
    size = 7 + resSize;
    printD ("ldapMessage size: Ox" << hex << size);

    // initialize message header
    data = new unsigned char[size];

    data[0] = MSG_LDAP;
    data[1] = size - 2; // except Ox3O LL FIXME handle long messages
    data[2] = MSG_ID;
    data[3] = MSG_ONE;
    data[4] = msgData.id;
    data[5] = msgData.responseProtocol;
    data[6] = resSize;

    // add rest of the message
    memcpy (data + 7, resData, resSize);
}

/**
 * ldap error message constructor
 **/
ldapMessage::ldapMessage (ldapErrorType type)
{
    data = NULL;
    size = 0;
}

/**
 * Message destructor
 **/
ldapMessage::~ldapMessage ()
{
    if (data) {
        delete[] data;
    }
}

/**
 * Data property getter
 **/
const unsigned char *
ldapMessage::getData () const
{
    return data;
}

/**
 * Size property getter
 **/
const size_t
ldapMessage::getSize () const
{
    return size;
}
