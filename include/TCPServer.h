#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <list>
#include <memory>
#include <ctime>
#include "Server.h"
#include "FileDesc.h"
#include "TCPConn.h"

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();

   void initWhitelist(std::string fname);
   std::vector<std::string> getWhitelist();

   bool isValidIP(TCPConn connection, std::string ipAddr);

   void writeToLog();

private:
   // Class to manage the server socket
   SocketFD _sockfd;
 
   // List of TCPConn objects to manage connections
   std::list<std::unique_ptr<TCPConn>> _connlist;

   // Whitelist Files
   std::string whitelistFile = "../src/data/whitelist.txt";    // Change to data/whitelist on submission
   std::vector<std::string> whitelist;
   int numWhitelisted = 0;

   // Logging
    std::string logFile = "../src/data/server.log";
    time_t tt;  //https://www.geeksforgeeks.org/c-program-print-current-day-date-time/
    struct tm * ti;
};


#endif
