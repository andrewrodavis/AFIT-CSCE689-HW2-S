//
// Created by andre on 1/29/2020.
//
#include <iostream>
#include "PasswdMgr.h"
#include "FileDesc.h"

void functionOne(){
    PasswdMgr manager("../src/data/authentication.txt", "../src/data/tempFile.txt");

//    if(manager.checkUser("username")){
//        std::cout << "User found\n";
//    }
    // Need to add the user
    std::string andrew = "Andrew";
    std::string andrewpd = "password";
    std::string andrewpdwrong = "assword";


    if(!manager.checkUser(andrew.c_str())){
        std::cout << "Adding Andrew\n";
        manager.addUser(andrew.c_str(), andrewpd.c_str());
    }
    manager.addUser("Julia", "pword");
//    // Check Andrew password
    if(manager.checkPasswd(andrew.c_str(), andrewpd.c_str())){
        std::cout << "Andrew pword good\n";
    }
}
int main(){
    FileFD pwfile("../src/data/authentication.txt");

    functionOne();

    return 0;
}

