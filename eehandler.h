
#ifndef __TCW_EVENT_HANDLER_H__
#define __TCW_EVENT_HANDLER_H__

#include "include.h"
#include "eeclient.h"
#include "eemodule.h"
#include "tortellini.h"

/** policy: read actively and write passively */

#define EPOLL_MAX_NUM       12

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
        static std::map<std::string, event_actions_t>    m_linkers_actions;  /** 服务名称, 执行动作 */
        static std::map<std::string, std::function<int(void*)>>   m_linkers_func;
        static bool                                         m_is_running;
        std::string                                         m_conf_name;        /** 记录配置名称 */
        SID_t                                               m_daemon_id;        /** 守护进程 id */
        bool                                                m_is_daemon;        /** 当前进程是否为守护进程 */
        /** 一个服务可能对应多个 SID, 所以这样映射 */
        std::unordered_map<SID_t, std::string>              m_services_id;      /** 服务 id, 服务名称 */
        SID_t                                               m_id;               /** 当前服务 id */
        /** m_clients = m_listeners 及其 clients 成员 + m_ilinkers + m_olinkers */
        std::map<FD_t, EClient*>                            m_clients;
        /** 接收或发送映射连接 */
        std::map<FD_t, SID_t>                               m_ilinkers;         /** 对内写连接映射 */
        std::map<FD_t, SID_t>                               m_olinkers;         /** 主动对外写连接映射 */
        std::map<SID_t, std::pair<FD_t, FD_t>>              m_pipe_pairs;       /** 管道符对 */
        /** 记录 m_ilinkers 和 m_olinkers 的写入队列 */
        /** A服务对应一个 queue, 其他服务会将生成或转发的消息输入到此队列，之后将队列内容写到A服务对应的套接字中 */
        /** 进程间消费队列 */
        std::map<SID_t, std::queue<std::string>>            m_linker_queues;    /** 服务ID，待写队列 */
        std::map<SID_t, uint64_t>                           m_heartbeats;
        std::map<pid_t, std::string>                        m_info_process;     /** 进程ID, 服务名称(处理僵尸进程) */
        Logger*                                             logger;
        tortellini::ini                                     m_ini;
        /** 应用层(eefunc)通信支持。 */
        /** 线程间消费队列。因为是线程间，所以不需要带服务id */
        std::queue<std::string>                             m_messages;
        std::mutex                                          m_mutex;
        std::condition_variable                             m_cond;
    public:
        static RetCode tcw_register_service(const std::string& service, int func(void*));
        RetCode tcw_init(const std::string& conf, const std::string& service = "");
        void tcw_destroy();
        RetCode tcw_add(EClient *ec);
        RetCode tcw_mod(EClient *ec, OPTION_t op);
        RetCode tcw_del(EClient *ec);
        void tcw_run();
        void tcw_clear_zombie();
        RetCode tcw_guard_child();
        void tcw_rebuild_child(int rfd, int wfd, const std::string& conf, const std::string& specified_service, const SID_t daemon_id);
        
        // TCP handler
        EClient* tcw_tcp_listen(std::string bind_ip, PORT_t service_port, SID_t sid, event_actions_t clients_action);
        EClient* tcw_tcp__accept(EListener *el);
        EClient* tcw_tcp_connect(std::string remote_ip, PORT_t remote_port, SID_t sid);
        // Pipe handler
        std::pair<EClient*, EClient*> tcw_pipe_create(FD_t rfd, FD_t wfd, SID_t sid);
    };
};

#endif // !__TCW_EVENT_HANDLER_H__