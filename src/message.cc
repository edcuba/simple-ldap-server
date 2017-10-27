#include "message.h"
#include "ldap.h"

using namespace std;

ldapMessage::ldapMessage (const ldapMessageData &msgData, const ldapResult &result)
{
    size_t resSize = result.getSize ();
    const char *resData = result.getData ();

    printD ("Result size: 0x" << hex << resSize);

    size = 7 + resSize;

    printD ("ldapMessage size: Ox" << hex << size);

    // initialize message header
    data = new unsigned char[size];

    data[0] = MSG_LDAP;
    data[1] = size - 2; // except Ox3O LL
    data[2] = MSG_ID;
    data[3] = MSG_ONE;
    data[4] = msgData.id;
    data[5] = msgData.responseProtocol;
    data[6] = resSize;

    // add rest of the message
    memcpy (data + 7, resData, resSize);
}

ldapMessage::ldapMessage (ldapErrorType type)
{
    data = NULL;
    size = 0;
}

ldapMessage::~ldapMessage ()
{
    if (data) {
        delete[] data;
    }
}

const unsigned char *
ldapMessage::getData () const
{
    return data;
}

const size_t
ldapMessage::getSize () const
{
    return size;
}
