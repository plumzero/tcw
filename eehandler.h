
#ifndef __Epoll_Event_HANDLER_H__
#define __Epoll_Event_HANDLER_H__

#include "include.h"
#include "eeclient.h"
#include "eemodule.h"
#include "tortellini.h"

/** policy: read actively and write passively */

#define EPOLL_MAX_NUM       12

namespace EEHNS
{   
    class Logger;

    typedef enum {
        EEH_OK          = 0,
        EEH_ERROR       = -1,
    } EEHErrCode;

    typedef EClient  EListener;

    class EpollEvHandler final
    {
    private:
        int                                                 m_epi;
        std::map<FD_t, SID_t>                               m_listeners;
        static std::map<std::string, ee_event_actions_t>    m_linkers_actions;  /** 服务名称, 执行动作 */
    public:
        static bool                                         m_is_running;
        std::unordered_map<SID_t, std::string>              m_services_id;      /** 服务 id, 服务名称 */
        SID_t                                               m_id;
        /** m_clients = m_listeners 及其 clients 成员 + m_ilinkers + m_olinkers */
        std::map<FD_t, EClient*>                            m_clients;
        /** 接收或发送映射连接 */
        std::map<FD_t, SID_t>                               m_ilinkers;         /** 对内写连接映射 */
        std::map<FD_t, SID_t>                               m_olinkers;         /** 主动对外写连接映射 */
        std::map<SID_t, std::pair<FD_t, FD_t>>              m_pipe_pairs;       /** 管道符对 */
        /** 记录 m_ilinkers 和 m_olinkers 的写入队列 */
        std::map<SID_t, std::queue<std::string>>            m_linker_queues;
        std::map<SID_t, uint64_t>     m_heartbeats;
        std::map<SID_t, std::pair<std::string, ee_event_actions_t>> m_linkers_map;
        std::map<pid_t, std::string>        m_info_process;                     /** 进程信息 */
        Logger*                             logger;
        tortellini::ini                     m_ini;

        ee_event_block_t                    m_info_block;       /** 测试用 */
    public:
        static EEHErrCode EEH_set_services(const std::string& service, const& ee_event_actions_t actions);
        EEHErrCode EEH_init(const std::string& conf);
        void EEH_destroy();
        EEHErrCode EEH_add(EClient *ec);
        EEHErrCode EEH_mod(EClient *ec, OPTION_t op);
        EEHErrCode EEH_del(EClient *ec);
        void EEH_run();
        void EEH_clear_zombie();
        
        // TCP handler
        EClient* EEH_TCP_listen(std::string bind_ip, PORT_t service_port, SID_t sid, ee_event_actions_t clients_action);
        EClient* EEH_TCP_accept(EListener *el);
        EClient* EEH_TCP_connect(std::string remote_ip, PORT_t remote_port, SID_t sid);
        // Pipe handler
        std::pair<EClient*, EClient*> EEH_PIPE_create(FD_t rfd, FD_t wfd, SID_t sid);
    };
};

#endif // !__Epoll_Event_HANDLER_H__