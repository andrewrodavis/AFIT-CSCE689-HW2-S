#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <sstream>
#include <PasswdMgr.h>
#include "TCPConn.h"
#include "strfuncts.h"

// The filename/path of the password file
const char pwdfilename[] = "../src/data/authentication.txt";    // ***********Change for submission, note paths in write-up
const char tempFile[] = "../src/data/tempFile.txt";

TCPConn::TCPConn(){ // LogMgr &server_log):_server_log(server_log) {

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   // Skipping this for now
   _status = s_username;

   _connfd.writeFD("Username: ");

}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();

            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
    // Insert your mind-blowing code here
    // File variables
    std::ifstream authenticationFile;
    authenticationFile.open(pwdfilename);
    std::string line;        // String used for reading from the file
    std::string uname;       // Used because...same as ss
    std::stringstream ss;;   // Used because need two delimiters in the authentication file, for now
    std::string newlineDelimiter = "\\n";   // \\n because of file setup when calling getline() -- reference line 143

    // Networking variables
    std::string readBuffer;

    // Utility variables
    int counter = 1;    // Used to alternate between username and password on file input. Start at 2 for modulo operations
    std::vector<std::string> usernames;     // Hold the usernames from the file

    if(authenticationFile){
        while ( getline(authenticationFile, line) ) {
            // Split username from file
            uname = line.substr(0, line.find(newlineDelimiter));
            usernames.push_back(uname);
        }
        authenticationFile.close();
    }
    else{
        std::cout << "No username file exists\n";
    }

    // read the date on the socket
    this->getUserInput(readBuffer);

    // Check to input against the username list
    // Look for the username in the vector
    std::vector<std::string>::iterator it = find(usernames.begin(), usernames.end(), readBuffer);
    // if here, username does not exist
    if(it == usernames.end()){
        this->sendText("Your username is not recognized. Good-Bye\n");
        this->disconnect();
        std::ofstream _server_log(this->logFile, std::ios::app);
        if(_server_log.is_open()){
            std::string ipaddr;
            _connfd.getIPAddrStr(ipaddr);
            time (&this->tt);
            ti = localtime(&this->tt);

            _server_log << "Failed connection attempt by " << readBuffer << ". IP: ipaddr" << "\t";
            _server_log << asctime(this->ti);
            _server_log << "\n";
            _server_log.close();
        }
        else{
            std::cout << "Error on opening log file, server.log\n";
        }
        // log file error
    }
    // username does exist
    else{
        this->_username = *it;
        _connfd.writeFD("Enter Password: ");
        this->_status = s_passwd;
    }
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your astounding code here

   PasswdMgr manager(pwdfilename, tempFile);  // Password Manager File
   std::string readBuffer;          // I/O Variables


   // Get the user's password
   this->getUserInput(readBuffer);

   if(manager.checkPasswd(this->_username.c_str(), readBuffer.c_str())){
       this->_pwd_attempts = 0;
       this->_status = s_menu;
       this->sendMenu();
       std::string ipaddr;
       _connfd.getIPAddrStr(ipaddr);
       std::ofstream _server_log(this->logFile, std::ios::app);
       if(_server_log.is_open()){
           time (&this->tt);
           ti = localtime(&this->tt);

           _server_log << "Successful connection by " << readBuffer << ". IP: " << ipaddr << "\t";
           _server_log << asctime(this->ti);
           _server_log << "\n";
           _server_log.close();
       }
       else{
           std::cout << "Error on opening log file, server.log\n";
       }
   }
   else{
       this->_pwd_attempts++;
   }
   if(this->_pwd_attempts == 1){
       this->sendText("Wrong. Try Again: ");
   }
   else if(this->_pwd_attempts == 2){
       this->sendText("You had your chance. Good-Bye\n");
       this->disconnect();
       std::ofstream _server_log(this->logFile, std::ios::app);
       std::string ipaddr;
       _connfd.getIPAddrStr(ipaddr);
       if(_server_log.is_open()){
           time (&this->tt);
           ti = localtime(&this->tt);

           _server_log << "Disconnected. Failed password attempt by " << this->_username << ". IP: " << ipaddr << "\t";
           _server_log << asctime(this->ti);
           _server_log << "\n";
           _server_log.close();
       }
       else{
           std::cout << "Error on opening log file, server.log\n";
       }
   }
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here
   PasswdMgr manager(pwdfilename, tempFile);

   // Get the user's new password input on status flag, end
   if(this->_status == s_changepwd){
       this->getUserInput(this->_newpwd);
       this->sendText("Re-enter: ");
       this->_status = s_confirmpwd;
   }
   else{
       // Helper variables
       PasswdMgr manager(pwdfilename, tempFile);
       std::string reEnteredPwd;

       this->getUserInput(reEnteredPwd);

       // This is a valid input. Therefore, change the password
       if(reEnteredPwd == this->_newpwd){
           if(manager.changePasswd(this->_username.c_str(), this->_newpwd.c_str()), tempFile){
               // Successful change
               this->sendText("Password Successfully Changed\n");
               this->sendText("Type <Menu> for...the menu\n");
               this->_status = s_menu;
           }
           else{
               this->sendText("Error Changing Password. Type <Menu> to go home.\n");
               this->_status = s_menu;
               //failed change
           }
       }
   }


}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
       std::ofstream _server_log(this->logFile, std::ios::app);
       if(_server_log.is_open()){
           std::string ipaddr;
           _connfd.getIPAddrStr(ipaddr);
           time (&this->tt);
           ti = localtime(&this->tt);

           _server_log << "Disconnected. " << this->_username << ". IP: " << ipaddr << "\t";
           _server_log << asctime(this->ti);
           _server_log << "\n";
           _server_log.close();
       }
       else{
           std::cout << "Error on opening log file, server.log\n";
       }
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      msg += "You want a prediction about the weather? You're asking the wrong Phil.\n";
      msg += "I'm going to give you a prediction about this winter. It's going to be\n";
      msg += "cold, it's going to be dark and it's going to last you for the rest of\n";
      msg += "your lives!\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("42\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("That seems like a terrible idea.\n");
   } else if (cmd.compare("4") == 0) {

   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("I'm singing, I'm in a computer and I'm siiiingiiiing! I'm in a\n");
      _connfd.writeFD("computer and I'm siiiiiiinnnggiiinnggg!\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Available choices: \n";
   menustr += "  1). Provide weather report.\n";
   menustr += "  2). Learn the secret of the universe.\n";
   menustr += "  3). Play global thermonuclear war\n";
   menustr += "  4). Do nothing.\n";
   menustr += "  5). Sing. Sing a song. Make it simple, to last the whole day long.\n\n";
   menustr += "Other commands: \n";
   menustr += "  Hello - self-explanatory\n";
   menustr += "  Passwd - change your password\n";
   menustr += "  Menu - display this menu\n";
   menustr += "  Exit - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 * Why does this return if it is void? What is the point of this function? Reference, but again,
 *          why return?
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

/**********************************************************************************************
 * checkValidIPAddr - Does exactly that. This function is called before any storage of the TCPConn
 *                 object in TCPServer.cpp
 *
 * Help: https://www.techiedelight.com/check-vector-contains-given-element-cpp/
 **********************************************************************************************/
 bool TCPConn::checkValidIPAddr(std::string &ipAddr, std::vector<std::string> theWhitelist){
    // If the element is on the whitelist, return true
    if(std::find(theWhitelist.begin(), theWhitelist.end(), ipAddr) != theWhitelist.end()){
        return true;
    }
    else{
        return false;
    }
 }
