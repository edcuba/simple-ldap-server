#include "server.h"
#include "ldap.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

using namespace std;

class ldapMsg
{
  public:
    ldapMsg (size_t size) { msg = new char[size]; }
    int len = 0;
    char *msg = NULL;
};

/**
 * Receive byte from client
 * @param client socket descriptor
 * @return single byte from socket
 **/
static inline int
receiveByte (int client)
{
    int data = 0;
    read (client, &data, 1);
    printD ("[" << client << "] Received: 0x" << hex << data);
    return data;
}

/**
 * Read message from TCP socket
 * @param client socket descriptor
 **/
static ldapMsg *
readMessage (int client)
{
    // read first two bytes expect LdapMessage - 0x30 and length of L1 message
    int type = receiveByte (client);

    if (type != MSG_LDAP) {
        printE ("Invalid message header: 0x" << hex << type);
        return NULL;
    }

    // get length of the message
    int len = receiveByte (client);

    if (len == 0) {
        printE("Invalid message length: " << len);
        return NULL;
    }

    ldapMsg *data = new ldapMsg (len);
    data->len = read (client, data->msg, len);
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
 * Handle client and exit
 * @param client socket descriptor
 **/
static void
handleClient (int client)
{
    printD ("Thread handling client " << client);

    ldapMsg *data = readMessage (client);

    if (data == NULL) {
        printD ("Warning: no data from client " << client);
        sclose (client);
        return;
    }

    printD ("Data length: " << data->len);

    if (DEBUG) {
        for (size_t i = 0; i < data->len; ++i) {
            cerr << "0x";
            cerr << hex << (int) data->msg[i];
            cerr << " ";
        }
        cerr << endl;
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
        thread worker = thread (handleClient, client);
        worker.detach ();
    }

    close (sd);
    return 0;
}
