#include "message.h"
#include "ber.h"
#include "ldap.h"

using namespace std;

/**
 * Result message contructor
 **/
ldapMessage::ldapMessage (const ldapMessageData &msgData, const string &result)
{
    // craft message body
    string body = encodeInt (msgData.id);
    body += (char) msgData.responseProtocol;
    body += encodeSize (result.size ());
    body += result;

    // craft final response
    data = encodeSeq (body);
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
