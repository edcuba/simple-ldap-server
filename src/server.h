#ifndef SERVER_H
#define SERVER_H

using namespace std;

#include "csv.h"
#include <vector>

class clientData
{
  public:
    clientData (int c, vector<entry> *d)
    {
        _client = c;
        _data = d;
    }

    int client () const { return _client; }
    vector<entry> *data () const { return _data; }

  protected:
    int _client;
    vector<entry> *_data;
};

#include "cli.h"
#include "ldap.h"

int
runServer (config &c);

unsigned char
receiveByte (int client);

bool
sendMessage (int client, ldapMessage &msg);

#endif
