
#ifndef __Epoll_Ev_MODULE_H__
#define __Epoll_Ev_MODULE_H__

#include "include.h"

typedef struct _struct_ee_event_actions {
    ssize_t (*do_read)(int fd, void *buf, size_t size, void *userp);
    ssize_t (*do_write)(int fd, const void *buf, size_t count, void *userp);
    int    (*do_timer)(void* args, void *userp);
} ee_event_actions_t;

extern ee_event_actions_t daemon_callback_module;
extern ee_event_actions_t child_callback_module;

#endif // ! __Epoll_Ev_MODULE_H__