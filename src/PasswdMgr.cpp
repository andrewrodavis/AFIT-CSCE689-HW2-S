#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <random>
#include <functional>
#include <fstream>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int HASHLEN = 32;
const int SALTLEN = 16;

PasswdMgr::PasswdMgr(const char *pwd_file, const char *temp_file){
    this->_pwd_file = pwd_file;
    this->_temp_file = temp_file;
}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *  Returns true if found, false if not
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;

   bool result = findUser(name, passwd, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {
   // Insert your insane code here
   FileFD pwfile(this->_pwd_file.c_str());
   FileFD tempFile(this->_temp_file.c_str());

   // File Looping Variables
   unsigned char tempByte;
   int byteCtr = 0;
   bool eof = false;
   std::string uname;

   std::vector<uint8_t> hash, salt, ret_hash;
   // Open the file
   if (!pwfile.openFile(FileFD::readfd)) {
       throw pwfile_error("Could not open passwd file for reading");
   }
    if (!tempFile.openFile(FileFD::writefd)) {
        throw pwfile_error("Could not open temp file for reading");
    }

   while(!eof){
       // reset variables
       uname.clear();
       hash.clear();
       salt.clear();
       // Grab data of person
       if(!this->readUser(pwfile, uname, hash, salt)){
           eof = true;
           continue;
       }
       // If the person is who you are looking for
           if(!uname.compare(name)){
           // Add their name to the new list
           tempFile.writeFD(uname);
           tempFile.writeFD("\n");
           // Get the hash of their new password
           this->hashArgon2(ret_hash, salt, passwd);
           // Store their new password in the file
           tempFile.writeFD("{");
           tempFile.writeBytes(ret_hash);
           tempFile.writeFD("}\n");
           // Store their salt in the file
           tempFile.writeFD("{");
           tempFile.writeBytes(salt);
           tempFile.writeFD("}\n");
       }
       // If it is not who you are looking for
       else{
           // Add the information to the temp file anyway
           tempFile.writeFD(uname);
           tempFile.writeFD("\n");
           tempFile.writeFD("{");
           tempFile.writeBytes(hash);
           tempFile.writeFD("}\n");
           tempFile.writeFD("{");
           tempFile.writeBytes(salt);
           tempFile.writeFD("}\n");
       }
   }

   // Now copy temp file back into the authentication file
   pwfile.closeFD();
   tempFile.closeFD();
    if (!pwfile.openFile(FileFD::writefd)) {
        throw pwfile_error("Could not open passwd file for reading");
    }
    if (!tempFile.openFile(FileFD::readfd)) {
        throw pwfile_error("Could not open passwd file for reading");
    }
   eof = false;
   while(!eof){
       uname.clear();
       hash.clear();
       salt.clear();
       if(!this->readUser(tempFile, uname, hash, salt)){
           eof = true;
           continue;
       }
       else{
           pwfile.writeFD(uname);
           pwfile.writeFD("\n");
           pwfile.writeFD("{");
           pwfile.writeBytes(hash);
           pwfile.writeFD("}\n");
           pwfile.writeFD("{");
           pwfile.writeBytes(salt);
           pwfile.writeFD("}\n");
       }
   }

   hash.clear();
   salt.clear();
   ret_hash.clear();
   pwfile.closeFD();
   tempFile.closeFD();
   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 * https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!
   // String Parsing Variables
   int byteCtr = 0;
   unsigned char tempByte;
   bool hashFlip = true;

   // Clear vectors
   hash.clear();
   salt.clear();

   // Grab username
   while(pwfile.readByte(tempByte)){
       if(byteCtr == 0 && tempByte == '\n'){
           // end of line
           break;
       }
       name.append(1, tempByte);
   }

   if(name == ""){
       return false;
   }

   while(pwfile.readByte(tempByte)){
       if(byteCtr == 0 && tempByte == '{'){
           continue;
       }
       if(byteCtr == HASHLEN && tempByte == '}'){
           byteCtr = 0;
           break;
       }
       hash.push_back(tempByte);
       byteCtr++;
   }
   while(pwfile.readByte(tempByte)){
       if((byteCtr == 0 && tempByte == '\n') || (byteCtr == 0 && tempByte == '{')){
           continue;
       }
       if(byteCtr == SALTLEN && tempByte == '}'){
           break;
       }
       salt.push_back(tempByte);
       byteCtr++;
   }
   // Get final newline to reset for subsequent readings from file
   pwfile.readByte(tempByte);

   // Debugging to check bytes
//    std::cout << "\n";
//   std::cout << "name: \n";
//    for(int i = 0; i < 6; i++){
//       fprintf(stdout, "%02X ", name[i]);
//   }
//   std::cout << "\n";
//    std::cout << "hash: \n";
//   for(int i = 0; i < HASHLEN; i++){
//       fprintf(stdout, "%02X ", hash[i]);
//   }
//    std::cout << "\n";
//   std::cout << "salt: \n";
//    for(int i = 0; i < SALTLEN; i++){
//        fprintf(stdout, "%02X ", salt[i]);
//    }
//    std::cout << "\n\n\n";
    return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // Insert your wild code here!
   // convert name var to unsigned char
   pwfile.writeByte(name);

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation
   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n

   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  ret_hash - the std string object to store the hash
 *             in_passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!

   // Hashing Variables
   uint32_t t_cost = 2;
   uint32_t m_cost = (1<<16);
   uint32_t parallelism = 1;

   // Convert password to uint8_t and get length
   uint8_t *pwd = (uint8_t *)strdup(in_passwd);
   uint32_t pwdlen = strlen((char *)pwd);

   // Convert vectors to arrays
   uint8_t hash[HASHLEN];
   uint8_t salt[SALTLEN];
    std::copy(ret_hash.begin(), ret_hash.end(), hash);
    std::copy(ret_salt.begin(), ret_salt.end(), salt);

    // High level API of argon
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, SALTLEN, hash, HASHLEN);

    // Convert arrays to vectors
    ret_hash.clear();
    ret_hash.insert(ret_hash.begin(), std::begin(hash), std::end(hash));
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 *    https://stackoverflow.com/questions/50441653/generate-array-of-random-16-byte-in-hex
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!

   // Writing to File Variables
    std::ofstream outputFile;
    std::string nameInStr(name);

    // Hashing Variables
   std::vector<uint8_t> hashedPasswd;       // Pass to the has function, this is the hashed password to store
   uint8_t saltArray[SALTLEN];
   std::vector<uint8_t> saltVector;

   // Randomly generate 16 bit salt
//   std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char> engine;
//   std::generate(begin(saltVector), end(saltVector), std::ref(engine));

    // Easy salt for now
    memset(saltArray, 0x00, SALTLEN);
    // Convert salt array to vector
    saltVector.insert(saltVector.begin(), std::begin(saltArray), std::end(saltArray));

    // Hash
    this->hashArgon2(hashedPasswd, saltVector, passwd, NULL);

   if(!this->checkUser(name)){
       // Open file for writing
       outputFile.open(this->_pwd_file, std::ios_base::app);
       if(outputFile.is_open()){
           outputFile << name << "\n{";
           for(auto it = hashedPasswd.begin(); it != hashedPasswd.end(); it++){
               outputFile << *it;
           }
           outputFile << "}\n{";
           for(auto it = saltVector.begin(); it != saltVector.end(); it++){
               outputFile << *it;
           }
           outputFile << "}\n";
       }
       else{
           // Error opening file
       }
   }
}

