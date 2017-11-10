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
 *  this is just empty message as we are not sending error reports
 **/
ldapMessage::ldapMessage (ldapErrorType type) {}

/**
 * dump ldapMessage
 **/
string
ldapMessage::dump ()
{
    return data;
}
