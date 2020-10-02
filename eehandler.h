
#ifndef __TCW_EVENT_HANDLER_H__
#define __TCW_EVENT_HANDLER_H__

#include "include.h"
#include "eeclient.h"
#include "eemodule.h"
#include "eehelper.h"
#include "tortellini.h"

/** policy: read actively and write passively */

#define EPOLL_MAX_NUM           256
#define HEART_BEAT_INTERVAL     1
#define HEART_BEAT_OFFLINE      4

namespace tcw
{   
    void signal_release(int signum);
    
    class Logger;

    typedef enum {
        OK          = 0,
        ERROR       = -1,
    } RetCode;

    typedef EClient  EListener;

    class EventHandler final
    {
    private:
        int                                                 m_epi;
        std::map<FD_t, SID_t>                               m_listeners;
    public:
        static std::map<std::string, event_actions_t>       m_linkers_actions;  /** service name, actions */
        static std::map<std::string, std::function<int(void*)>>   m_linkers_func;
        static std::map<std::string, std::function<void(const uint16_t, const uint64_t, uint64_t, const std::string&, void*)>> m_service_callback;
        static bool                                         m_is_running;
        std::string                                         m_conf_name;
        SID_t                                               m_daemon_id;
        bool                                                m_is_daemon;
        std::unordered_map<SID_t, std::string>              m_services_id;      /** service id, service name */
        SID_t                                               m_id;               /** current service id */
        std::map<FD_t, EClient*>                            m_clients;          /** m_clients = m_listeners(clients included) + m_ilinkers + m_olinkers */
        std::map<FD_t, SID_t>                               m_ilinkers;         /** inward writie linker map */
        std::map<FD_t, SID_t>                               m_olinkers;         /** outward write linker map */
        std::map<SID_t, std::pair<FD_t, FD_t>>              m_pipe_pairs;       /** pipes pair(may not used temporarily) */
        /** queues between two process (writing queues for m_ilinkers and m_olinkers) */
        std::map<SID_t, std::queue<std::string>>            m_linker_queues;    /** service id，queue for writing */
        std::map<SID_t, uint64_t>                           m_heartbeats;
        std::map<SID_t, BitRing<HEART_BEAT_OFFLINE>>        m_hb_offline;
        std::map<pid_t, std::string>                        m_info_process;     /** pid, service name(use for dealing with zombie process) */
        std::unordered_map<SID_t, std::set<FD_t>>           m_route_fd;         /** used at tcp server side, key is the sid that orient to from tcp server, val is fd to remote proxy/client  */
        Logger*                                             logger;
        tortellini::ini                                     m_ini;
        /** queues between IO thread and user-service thread */
        std::queue<std::string>                             m_messages;
        std::mutex                                          m_mutex;
        std::condition_variable                             m_cond;
    public:
        static RetCode tcw_register_service(const std::string& service, int func(void*));
        static RetCode tcw_register_service_2(const std::string& service, void func(const uint16_t, const uint64_t, const uint64_t, const std::string&, void* arg));
        RetCode tcw_init(const std::string& conf, const std::string& service = "");
        void tcw_destroy();
        RetCode tcw_add(EClient *ec);
        RetCode tcw_mod(EClient *ec, OPTION_t op);
        RetCode tcw_del(EClient *ec);
        void tcw_run();
        void tcw_clear_zombie();
        RetCode tcw_guard_child();
        void tcw_rebuild_child(int rfd, int wfd, const std::string& conf, const std::string& specified_service, const SID_t daemon_id);
        RetCode tcw_check_message(const std::string& stream, uint16_t* msgid, uint64_t* origin, uint64_t* orient, std::string* msg);
        RetCode tcw_send_message(const uint16_t msgid, const uint64_t tosid, const std::string& msg);
        uint64_t tcw_get_sid(const std::string& service);   /** interface for testing */
        
        // TCP handler
        EClient* tcw_tcp_listen(std::string bind_ip, PORT_t service_port, SID_t sid, event_actions_t clients_action);
        EClient* tcw_tcp_accept(EListener *el);
        EClient* tcw_tcp_connect(std::string remote_ip, PORT_t remote_port, SID_t sid);
        // Pipe handler
        std::pair<EClient*, EClient*> tcw_pipe_create(FD_t rfd, FD_t wfd, SID_t sid);
    };
};

#endif // !__TCW_EVENT_HANDLER_H__