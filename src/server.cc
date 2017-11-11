#include "server.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include "message.h"

using namespace std;

/**
 * Receive byte from client
 * @param client socket descriptor
 * @return single byte from socket
 **/
unsigned char
receiveByte (int client)
{
    unsigned char data = 0;
    read (client, &data, 1);
    printD ("[" << client << "] Received: 0x" << hex << (int) data);
    return data;
}

/**
 * Read single byte from socket descriptor and count in to actual level
 **/
unsigned char
ldapContext::getByte ()
{
    received++;
    return receiveByte (client);
}

/**
 * Read property length
 * length > 127 is specified on multiple bytes
 **/
size_t
ldapContext::readLength ()
{
    unsigned char data = getByte ();
    if (data < 0x80) {
        // encoded on single octet
        return data;
    }
    size_t res = 0;
    unsigned char octets = data - 0x80;
    for (int i = octets - 1; i >= 0; --i) {
        size_t d = getByte ();
        res |= d << (i * 8);
    }
    return res;
}

/**
 * Read INTEGER encoded according to BER
 * Ox02 [n: number of octets] [octet 1] ... [octet n]
 **/
int
ldapContext::readInt ()
{
    unsigned char data = getByte (); // 0x02
    (void) data;

    data = getByte (); // number of octets

    int res = 0;

    // contruct result
    for (int i = data - 1; i >= 0; --i) {
        int d = getByte ();
        res |= d << (8 * i);
    }

    return res;
}

/**
 * Read length and attribute from stream
 * @return attribute or NULL of length is zero
 **/
string
ldapContext::readAttr ()
{
    size_t len = readLength ();
    printD ("Attribute length: " << dec << (int) len);

    string data;
    if (len == 0) {
        return data;
    }
    for (size_t i = 0; i < len; ++i) {
        data += getByte ();
    }
    printD ("Received attribute: " << data);
    return data;
}

/**
 * Close socket and print debug line if applicable
 * @param client socket descriptor
 **/
static inline void
sclose (int client)
{
    close (client);
    printD ("Client " << client << " closed");
}

/**
 * Send ldapMessage to client
 **/
bool
sendMessage (int client, ldapMessage &msg)
{
    string data = msg.dump ();
    if (!data.empty ()) {
        if (DEBUG) {
            printD ("[Client " << client << "] Response message:");
            for (auto e : data) {
                int d = e;
                cerr << " 0x" << hex << d;
            }
            cerr << endl;
        }
        write (client, data.c_str (), data.size ());
        return true;
    }
    return false;
}

/**
 * Handle client and exit
 * @param client socket descriptor
 **/
static void
handleClient (clientData cd)
{
    const int client = cd.client ();

    printD ("Thread handling client " << client);

    while (true) {
        ldapMessage response = processMessage (cd);
        if (!sendMessage (client, response)) {
            break;
        }
    }
    sclose (client);
}

/**
 * Setup welcoming socket
 * @param port server port
 * @return socket descriptor
 **/
static int
createSocket (int port)
{
    int sd = -1;
    if ((sd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        pError ("socket()");
        return -1;
    }

    sockaddr_in socketInfo;
    socketInfo.sin_family = AF_INET;
    socketInfo.sin_port = htons (port);
    socketInfo.sin_addr.s_addr = INADDR_ANY;

    if (bind (sd, (sockaddr *) &socketInfo, sizeof (socketInfo)) == -1) {
        pError ("bind()");
        close (sd);
        return -1;
    }

    if (listen (sd, 64) == -1) {
        pError ("listen()");
        close (sd);
        return -1;
    }
    return sd;
}

/**
 * setup welcoming socket and wait for connection
 * create new threads for incomming clients
 *
 * @param c server configuration
 *
 * @return 0 if successfull
 **/
int
runServer (config &c)
{
    // set up socket
    int sd = createSocket (c.port);
    if (sd == -1) {
        return 1;
    }

    printD ("Created socket with descriptor " << sd << " on port " << c.port);

    int client;
    socklen_t addrlen;
    sockaddr_in cInfo;

    printD ("Waiting for connection");

    // accept connections
    while (true) {
        addrlen = sizeof (cInfo);

        client = accept (sd, (sockaddr *) &cInfo, &addrlen);
        if (client == -1) {
            pError ("accept()");
            close (sd);
            return -1;
        }

        printD ("Request from " << inet_ntoa (cInfo.sin_addr) << ":" << ntohs (cInfo.sin_port));

        // create thread to handle client
        thread worker = thread (handleClient, clientData (client, c.data));
        worker.detach ();
    }

    close (sd);
    return 0;
}
