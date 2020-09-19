
#ifndef __Epoll_Ev_FUNC_H__
#define __Epoll_Ev_FUNC_H__

#include "include.h"

/** help function in the file */
class BIC_BASE;
int check_message(const std::string& msg, uint64_t* fromsid, uint64_t* tosid, int32_t* mtype, void* args);
int send_message(const int32_t mtype, const uint64_t tosid, BIC_BASE* tobicp, void* args);

/** test function */
void* server_function(void* args);
void* client_function(void* args);

/** IPC between sub process */
void* step_1_function(void* args);
void* step_2_function(void* args);
void* step_3_function(void* args);


#endif // ! __Epoll_Ev_FUNC_H__