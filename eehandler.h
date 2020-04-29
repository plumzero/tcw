
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
    typedef _linker_or_server_type  SERVER_TYPE;

    class EpollEvHandler
    {
    private:
        int                                 m_epi;
        std::mutex                          m_mutex;
        std::condition_variable             m_cond;
        EEHErrCode                          m_errcode;
        
        std::vector<SERVER_TYPE>            m_serv_types;
        std::map<FD_t, SERVER_TYPE>         m_listeners;
    public:
        static bool                         m_is_running;
        static std::map<_linker_or_server_type, std::pair<std::string, ee_event_actions_t> > m_linkers_map;
        SERVER_TYPE                         m_type;
        /** m_clients = m_listeners 及其 clients 成员 + m_ilinkers + m_olinkers */
        std::map<FD_t, EClient*>            m_clients;
        /** 接收或发送映射连接 */
        std::map<FD_t, LINKER_TYPE>         m_ilinkers;                     /** 对内写连接映射 */
        std::map<FD_t, LINKER_TYPE>         m_olinkers;                     /** 主动对外写连接映射 */
        std::map<LINKER_TYPE, std::pair<FD_t, FD_t> > m_pipe_pairs;         /** 管道符对 */
        /** 记录 m_ilinkers 和 m_olinkers 的写入队列 */
        std::map<LINKER_TYPE, std::queue<std::string> > m_linker_queues;
        std::map<LINKER_TYPE, uint64_t>     m_heartbeats;
        static std::map<pid_t, std::string> m_info_process;     /** 进程信息 */
        ee_event_block_t                    m_info_block;       /** 测试用 */
        Logger*                             logger;
        tortellini::ini                     m_ini;
    public:
        EEHErrCode EEH_init(SERVER_TYPE type);
        void EEH_destroy();
        EEHErrCode EEH_add(EClient *ec);
        EEHErrCode EEH_mod(EClient *ec, OPTION_t op);
        EEHErrCode EEH_del(EClient *ec);
        void EEH_run();
        static void EEH_clear_zombie(void* userp);
        
        // TCP handler
        EClient* EEH_TCP_listen(std::string bind_ip, PORT_t service_port, SERVER_TYPE server_type,
                                                                    ee_event_actions_t clients_action);
        EClient* EEH_TCP_accept(EListener *el);
        EClient* EEH_TCP_connect(std::string remote_ip, PORT_t remote_port, LINKER_TYPE);
        // Pipe handler
        std::pair<EClient*, EClient*> EEH_PIPE_create(FD_t rfd, FD_t wfd, LINKER_TYPE linker_type);
        inline EEHErrCode EEH_last_error() { EEHErrCode ret = m_errcode; m_errcode = EEH_OK; return ret; }
    };
};

#endif // !__Epoll_Event_HANDLER_H__