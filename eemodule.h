
#ifndef __Epoll_Ev_MODULE_H__
#define __Epoll_Ev_MODULE_H__

#include "include.h"

typedef struct _struct_ee_event_actions {
	ssize_t (*do_read)(int fd, void *buf, size_t size, void *userp);
	ssize_t (*do_write)(int fd, const void *buf, size_t count, void *userp);
	int    (*do_timer)(void* args, void *userp);
} ee_event_actions_t;

struct ee_event_block_t {
	int          use;
	
	int          bictype;
	std::string  name;
	uint32_t     size;
	uint32_t     offset;
	uint32_t     blocksize;
	std::string *bicmsg;
	
	ee_event_block_t()
		: use(0), bictype(0), name(""), size(0), offset(0), blocksize(0), bicmsg(nullptr) {}
	~ee_event_block_t(){}
};

/****************************** 程序员声明 ******************************/

extern ee_event_actions_t null_callback_module;
extern ee_event_actions_t transfer_callback_module;
extern ee_event_actions_t madolche_callback_module;
extern ee_event_actions_t gimmickpuppet_callback_module;
extern ee_event_actions_t policy_callback_module;

typedef void(serialize_cb)(EEHNS::LINKER_TYPE linker_type, void *user_data);

void signal_release(int signum);

#endif // ! __Epoll_Ev_MODULE_H__