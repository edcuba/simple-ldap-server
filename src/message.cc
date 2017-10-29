#include "message.h"
#include "ldap.h"

using namespace std;

/**
 * Result message contructor
 **/
ldapMessage::ldapMessage (const ldapMessageData &msgData, const string &result)
{
    // craft message body
    string body;
    body += (char) 0x02;
    body += (char) 0x01;
    body += (char) msgData.id;
    body += (char) msgData.responseProtocol;
    body += (char) result.size ();
    body += result;

    // craft final response
    data.clear ();
    data += (char) 0x30;
    data += (char) body.size ();
    data += body;
}

/**
 * ldap error message constructor
 **/
ldapMessage::ldapMessage (ldapErrorType type)
{
    // TODO
}

/**
 * dump ldapMessage
 **/
string
ldapMessage::dump ()
{
    return data;
}
