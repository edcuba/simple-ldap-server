#include "server.h"
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
 * Read message from TCP socket
 * @param client socket descriptor
 **/
static ldapMsg *
readMessage (int client)
{
    // get length of the message
    int len = 0;
    ioctl (client, FIONREAD, &len);

    if (len > 0) {
        ldapMsg *data = new ldapMsg(len);
        data->len = read (client, data->msg, len);
        return data;
    }

    return NULL;
}

/**
 * Handle client and exit
 * @param client socket descriptor
 **/
static void
handleClient (int client)
{
    ldapMsg *data = readMessage (client);
    cout << "Data length: " << data->len << endl;
    for (size_t i = 0; i < data->len; ++i) {
        cout << "0x";
        cout << hex << (int)data->msg[i];
        cout << " ";
    }
    cout << endl;
    close (client);
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

    // accept connections
    while (true) {
        addrlen = sizeof (cInfo);

        printD ("Waiting for connection");

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
