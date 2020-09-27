
#ifndef __TCW_IO_MODULE_H__
#define __TCW_IO_MODULE_H__

#include "include.h"

typedef struct _struct_ee_event_actions {
    ssize_t (*do_read)(int fd, void *buf, size_t size, void *userp);
    ssize_t (*do_write)(int fd, const void *buf, size_t count, void *userp);
    int    (*do_timer)(void* args, void *userp);
} event_actions_t;

extern event_actions_t daemon_callback_module;
extern event_actions_t child_callback_module;

#endif // ! __TCW_IO_MODULE_H__