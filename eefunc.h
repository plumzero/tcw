
#ifndef __TCW_SERVICE_H__
#define __TCW_SERVICE_H__

#include "include.h"

/** help function in the file */
int check_message(const std::string& stream, uint16_t* msgid, uint64_t* origin, uint64_t* orient, std::string* msg, void* args);
int send_message(const uint16_t msgid, const uint64_t tosid, const std::string& msg, void* args);

/** test function */
int server_function(void* args);
int client_function(void* args);

#endif // ! __TCW_SERVICE_H__