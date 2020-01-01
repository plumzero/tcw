
#include "eehandler.h"

/**
 * 随笔:
 *   1. 对稳定信号(signal∈[SIGRTMIN, SIGRTMAX])的屏蔽是没必要的;
 *   2. nginx 对线程池的实现中，没有对 SIGILL, SIGFPE, SIGSEGV, SIGBUS 信号进行屏蔽;
 *   3. 通信端作为服务端时，一般对 SIGPIPE 信号进行屏蔽;
 *   4. 不要对一些结构体(尤其是包含 std::string 成员变量的结构体)使用 memset;
 */

namespace EEHNS
{   
    std::map<_linker_or_server_type, std::pair<std::string, ee_event_actions_t> > 
    EpollEvHandler::m_linkers_map = {
        { LINKER_TYPE_POLICY,        std::make_pair("POLICY",         policy_callback_module) },
        { SERVER_TYPE_TRANSFER,      std::make_pair("TRANSFER",       transfer_callback_module) },
        { SERVER_TYPE_ROVER,         std::make_pair("ROVER",          null_callback_module) },
        { SERVER_TYPE_SYNCHRON,      std::make_pair("SYNCHRON",       null_callback_module) },
        { SERVER_TYPE_RESONATOR,     std::make_pair("RESONATOR",      null_callback_module) },
        { LINKER_TYPE_MADOLCHE,      std::make_pair("MADOLCHE",       madolche_callback_module) },
        { LINKER_TYPE_CHRONOMALY,    std::make_pair("CHRONOMALY",     null_callback_module) },
        { LINKER_TYPE_GIMMICKPUPPET, std::make_pair("GIMMICK PUPPET", gimmickpuppet_callback_module) },
    };
    
    std::map<pid_t, std::string> EpollEvHandler::m_info_process = std::map<pid_t, std::string>();
    
    bool EpollEvHandler::m_is_running = false;
    
    EEHErrCode EpollEvHandler::EEH_init(SERVER_TYPE type)
    {
        sigset_t set;
        sigemptyset(&set);
        
        int i;
        for (i = SIGRTMIN; i <= SIGRTMAX; i++) {
            sigaddset(&set, i);
        }
        sigaddset(&set, SIGPIPE);
        int ret = pthread_sigmask(SIG_SETMASK, &set, NULL);
        if (ret) {
            ECHO(ERRO, "pthread_sigmask %s", strerror(errno));
            return EEH_ERROR;
        }
        
        signal(SIGINT, signal_release);

        m_listeners.clear();
        m_clients.clear();
        m_serv_types.clear();
        
        m_serv_types.push_back(SERVER_TYPE_SYNCHRON);
        m_serv_types.push_back(SERVER_TYPE_RESONATOR);
        m_serv_types.push_back(LINKER_TYPE_POLICY);
        
        m_epi = -1;
        m_type = type;
        
        if (m_type == SERVER_TYPE_TRANSFER) {
            m_heartbeats[LINKER_TYPE_MADOLCHE] = now_time();
            m_heartbeats[LINKER_TYPE_GIMMICKPUPPET] = now_time();
        }
        
        m_is_running = false;
        
        m_epi = epoll_create(EPOLL_MAX_NUM);
        if (m_epi < 0) {
            ECHO(ERRO, "epoll_create: %s", strerror(errno));
            return EEH_ERROR;
        }
                
        ECHO(INFO, "eehandler created.");
        
        return EEH_OK;
    }

    void EpollEvHandler::EEH_destroy()
    {
        ECHO(INFO, "%d cs(%d ls, %d ils, %d ols) would be destroyed.", 
                        m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size());
        
        m_serv_types.clear();
        m_listeners.clear();
        m_ilinkers.clear();
        m_olinkers.clear();

        std::map<FD_t, EClient*>::iterator iter_m;
        for (iter_m = m_clients.begin(); iter_m != m_clients.end(); iter_m++) {
            if (iter_m->first > 0) {
                close(iter_m->first);
            }
            if (iter_m->second != nullptr) {
                delete iter_m->second;
                iter_m->second = nullptr;
            }
        }
        m_clients.clear();
                
        m_is_running = false;
        m_info_process.clear();
        
        if (m_epi > 0)
            close(m_epi);
        
        ECHO(INFO, "eehandler destroyed.");
    }
    
    EEHErrCode EpollEvHandler::EEH_add(EClient *ec)
    {
        if (! ec)
            return EEH_ERROR;
        
        BaseClient *bc = dynamic_cast<BaseClient*>(ec);
        if (! bc)
            return EEH_ERROR;
        
        if (bc->fd <= 0)
            return EEH_ERROR;
        
        if (epoll_ctl(m_epi, EPOLL_CTL_ADD, bc->fd, &bc->ev) == -1) {
            ECHO(ERRO, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
            return EEH_ERROR;
        }
        
        if (m_clients.find(bc->fd) == m_clients.end()) {
            m_clients[bc->fd] = ec;
        }
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d, type=%d, option=%d) add to eehandler.",
                                            bc, bc->id, bc->fd, bc->type, bc->prev_option);
        
        return EEH_OK;
    }

    EEHErrCode EpollEvHandler::EEH_mod(EClient *ec, OPTION_t op)
    {
        if (! ec)
            return EEH_ERROR;
        
        BaseClient *bc = dynamic_cast<BaseClient*>(ec);
        if (! bc)
            return EEH_ERROR;
        
        if (bc->fd <= 0)
            return EEH_ERROR;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d, type=%d) mod option(%d->%d).",
                                            bc, bc->id, bc->fd, bc->type, bc->ev.events, op);
        
        bc->ev.events = op;
                
        if (epoll_ctl(m_epi, EPOLL_CTL_MOD, bc->fd, &bc->ev) == -1) {
            ECHO(ERRO, "epoll_ctl(EPOLL_CTL_MOD): %s", strerror(errno));
            return EEH_ERROR;
        }
        
        return EEH_OK;
    }
    
    EEHErrCode EpollEvHandler::EEH_del(EClient *ec)
    {
        if (! ec)
            return EEH_OK;

        bool exist = false;
        std::map<FD_t, EClient*>::iterator iter_m;
        for (iter_m = m_clients.begin(); iter_m != m_clients.end(); iter_m++) {
            if (iter_m->second == ec) {
                exist = true;
                break;
            }
        }
        if (! exist) {
            return EEH_OK;
        }
        
        BaseClient *bc = dynamic_cast<BaseClient*>(ec);
        if (! bc)
            return EEH_OK;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d, type=%d, is_server=%d) delete from eehandler.",
                                                            bc, bc->id, bc->fd, bc->type, bc->is_server);
        
        if (bc->fd <= 0) {
            /** an exception occurs, but do nothing */
        }
            
        if (epoll_ctl(m_epi, EPOLL_CTL_DEL, bc->fd, &bc->ev) == -1) {
            ECHO(ERRO, "epoll_ctl(EPOLL_CTL_DEL): %s", strerror(errno));
            /** an exception occurs, but do nothing */
        }

        if (bc->type == EEH_TYPE_TCP) {
            if (bc->is_server) {    /** as server */
                std::list<EClient*>::iterator iter_l;
                for (iter_l = bc->clients.begin(); iter_l != bc->clients.end(); iter_l++) {
                    BaseClient *bcc = dynamic_cast<BaseClient*>(*iter_l);
                    if (bcc) {
                        bcc->linker_type = SERVER_TYPE_ROVER;
                    } else {
                        /** an exception occurs, but do nothing */
                    }
                }

                if (m_listeners.erase(bc->fd) == 1) {
                    // DBUG("erase success");
                } else {
                    /** an exception occurs, but do nothing */
                }
            } else {    /** as connect client */
                if (bc->linker_type != SERVER_TYPE_ROVER) {
                    FD_t sfd = 0;
                    std::map<FD_t, SERVER_TYPE>::iterator iter_m;
                    for (iter_m = m_listeners.begin(); iter_m != m_listeners.end(); iter_m++) {
                        if (iter_m->second == bc->linker_type) {
                            sfd = iter_m->first;
                            break;
                        }
                    }
                    if (sfd > 0) {
                        BaseClient *bcs = dynamic_cast<BaseClient*>(m_clients[sfd]);
                        if (! bcs) {
                            ECHO(ERRO, "unexcepted logical fatal occurred");
                            return EEH_ERROR;
                        }

                        std::list<EClient*>::iterator iter_find = std::find(bcs->clients.begin(), bcs->clients.end(), ec);
                        if (iter_find != bcs->clients.end()) {
                            bcs->clients.erase(iter_find);
                        } else {
                            // DBUG("could not find it");
                        }
                    } else {
                        ECHO(INFO, "eclient(%p, fd=%d) is an active connect client", bc, bc->fd);
                    }
                } else {
                    // DBUG("tcp rover or other client, delete directly");
                }
            }
        } else {
            // DBUG("other eeh type");
        }
        
        if (m_ilinkers.erase(bc->fd) == 1) {
            
        } else if (m_olinkers.erase(bc->fd) == 1) { 
        
        } else {
            /** an exception occurs, but do nothing */
        }
        
        if (m_pipe_pairs.erase(bc->linker_type) == 1) {
            
        } else {
            
        }
        
        if (m_clients.erase(bc->fd) == 1) {
            // DBUG("erase success");
        } else {
            /** an exception occurs, but do nothing */
        }       
        if (bc->fd > 0) {
            // DBUG("close fd(%d)", bc->fd);
            close(bc->fd);
        } else {
            /** an exception occurs, but do nothing */
        }
        
        delete ec;
        ec = nullptr;
        
        ECHO(INFO, "erase success. remain: cs=%d(ls=%d, ils=%d, ols=%d, pps=%d)", 
            m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size(), m_pipe_pairs.size());
        
        return EEH_OK;
    }
    
    EClient* EpollEvHandler::EEH_TCP_listen(std::string bind_ip, PORT_t service_port, 
                                            SERVER_TYPE server_type, ee_event_actions_t clients_action)
    {
        if (std::find(m_serv_types.begin(), m_serv_types.end(), server_type) == m_serv_types.end()) {
            ECHO(ERRO, "illegal server type(%d)", server_type);
            return nullptr;
        }

        for (std::map<FD_t, SERVER_TYPE>::const_iterator it_m = m_listeners.begin(); it_m != m_listeners.end(); it_m++) {
            if (it_m->second == server_type) {
                ECHO(ERRO, "server type(%d) exist!", server_type);
                return nullptr;
            }
        }
        
        struct addrinfo hints, *addr_list, *cur;
        int on, sys_err;
        int lfd;
        
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;
        
        char buf[16];
        int n;
        n = snprintf(buf, 16, "%d", service_port);
        if (n < 0 || n >= 16) {
            return nullptr;
        }
        
        if (getaddrinfo(bind_ip.c_str(), std::string(buf, n).c_str(), &hints, &addr_list) != 0) {
            ECHO(ERRO, "getaddrinfo: %s", strerror(errno));
            return nullptr;
        }
        
        for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
            lfd = (int) socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
            if (lfd < 0) {
                continue;
            }
            
            on = 1;
            if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) != 0) {
                close(lfd);
                continue;
            }
            
            if (fcntl(lfd, F_SETFD, FD_CLOEXEC) == -1) {
                close(lfd);
                continue;
            }
            
            if (bind(lfd, cur->ai_addr, cur->ai_addrlen) != 0) {
                close(lfd);
                continue;
            }
            
            if (listen(lfd, 8) == -1) {
                close(lfd);
                continue;
            }
            
            on = 1;
            if (ioctl(lfd, FIONBIO, (const char *)&on) == -1) {
                close(lfd);
                continue;
            }
            
            break;
        }
        
        if (cur == NULL) {
            sys_err = errno;
            if (lfd > 0)
                close(lfd);
            ECHO(ERRO, "listen(%s:%d): %s", bind_ip.c_str(), service_port, strerror(sys_err));
            
            freeaddrinfo(addr_list);
            return nullptr;
        }
        
        freeaddrinfo(addr_list);
        
        BaseClient *tc = new TcpClient(lfd, bind_ip, service_port, true);
        if (! tc)
            return nullptr;
        
        int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        
        tc->prev_option = op;
        tc->linker_type = server_type;
        
        tc->ev.events = op;
        tc->ev.data.ptr = tc;
        
        tc->is_server = true;
        tc->clients_do = clients_action;
        m_listeners[tc->fd] = server_type;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d) as TCP server(%s:%d) listend.", 
                            tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
        
        return tc;
    }

    EClient* EpollEvHandler::EEH_TCP_accept(EListener *el)
    {
        if (! el)
            return nullptr;
        
        BaseClient *bl = dynamic_cast<BaseClient*>(el);
        
        int cfd = -1;
        int type;
        socklen_t type_len = (int)sizeof(type);
        
        if (getsockopt(bl->fd, SOL_SOCKET, SO_TYPE, (void*)&type, &type_len) != 0 || 
            (type != SOCK_STREAM)) {
            ECHO(ERRO, "getsockopt(SOL_SOCKET, SO_TYPE): %s", strerror(errno));
            return nullptr;
        }
        
        ECHO(INFO, "listener(%p, fd=%d, id=%d, port=%d, prev_option=%d) would accept a connect.",
                                bl, bl->fd, bl->id, bl->port, bl->prev_option);
        
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = (int)sizeof(client_addr);
        int try_times = 10;
        while ((cfd = accept(bl->fd, (struct sockaddr*)&client_addr, &client_addr_len)) == -1) {
            if (errno != EINTR && errno != ECONNABORTED) {
                ECHO(ERRO, "accept: %s", strerror(errno));
                return nullptr;
            }
            if (try_times-- == 0)
                return nullptr;
        }
        
        int on = 1;
        if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
            ECHO(ERRO, "ioctl(FIONBIO): %s", strerror(errno));
            close(cfd);
            return nullptr;
        }
        
        on = 1;
        if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on)) != 0) {
            ECHO(ERRO, "setsockopt(IPPROTO_TCP, TCP_NODELAY): %s", strerror(errno));
            close(cfd);
            return nullptr;
        }
        
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
        if (getnameinfo((struct sockaddr *)&client_addr, client_addr_len, 
                        hbuf, NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICSERV) != 0) {
            close(cfd);
            ECHO(ERRO, "getnameinfo: %s", strerror(errno));
            return nullptr;
        }

        BaseClient *tc = new TcpClient(cfd, hbuf, atoi(sbuf));
        if (! tc)
            return nullptr;
        
        int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        tc->prev_option = op;
        
        tc->host = inet_ntoa(client_addr.sin_addr);
        tc->port = ntohs(client_addr.sin_port);
        
        tc->ev.events = op;
        tc->ev.data.ptr = tc;
        
        tc->linker_type = bl->linker_type;
        
        tc->set_actions(bl->clients_do);
        
        bl->clients.push_back(tc);
        
        m_olinkers[tc->fd] = tc->linker_type;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                        tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
        
        return tc;
    }
    
    EClient* EpollEvHandler::EEH_TCP_connect(std::string remote_ip, PORT_t remote_port, LINKER_TYPE linker_type)
    {
        for (std::map<FD_t, LINKER_TYPE>::const_iterator it_m = m_olinkers.begin(); it_m != m_olinkers.end(); it_m++) {
            if (it_m->second == linker_type) {
                ECHO(ERRO, "linker type(%d) exist!", linker_type);
                return nullptr;
            }
        }
        
        int cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (cfd == -1) {
            ECHO(ERRO, "socket: %s", strerror(errno));
            return nullptr;
        }
            
        struct sockaddr_in sai;
        
        memset(&sai, 0, sizeof(sai));
        sai.sin_family = AF_INET;
        sai.sin_addr.s_addr = inet_addr(remote_ip.c_str());
        sai.sin_port = htons(remote_port);
        int try_times = 10;
        
        while (connect(cfd, (struct sockaddr*)&sai, sizeof(struct sockaddr_in)) == -1 && errno != EISCONN) {
            if (errno != EINTR) {
                ECHO(ERRO, "connect: %s", strerror(errno));
                close(cfd);         /// 后面添加一个 m_errcode, eeh 不背锅
                return nullptr;
            }
            if (try_times-- == 0)
                return nullptr;
        }
        
        int on = 1;
        if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
            close(cfd);
            return nullptr;
        }
        
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(struct sockaddr_in);
        if (getsockname(cfd, (struct sockaddr*)&client_addr, &client_addr_len) != 0) {
            ECHO(ERRO, "getsockname: %s", strerror(errno));
            close(cfd);
            return nullptr;
        }
        
        BaseClient *tc = new TcpClient(cfd, remote_ip, remote_port);
        if (! tc)
            return nullptr;
        
        int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;

        tc->prev_option = op;
        
        tc->host = inet_ntoa(client_addr.sin_addr);
        tc->port = ntohs(client_addr.sin_port);
        
        tc->ev.events = op;
        tc->ev.data.ptr = tc;
        
        tc->linker_type = linker_type;

        m_olinkers[tc->fd] = tc->linker_type;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                        tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
                        
        return tc;
    }
    
    std::pair<EClient*, EClient*> EpollEvHandler::EEH_PIPE_create(FD_t rfd, FD_t wfd, LINKER_TYPE linker_type)
    {
        std::pair<EClient*, EClient*> pipe_pair(nullptr, nullptr);
        
        for (std::map<FD_t, LINKER_TYPE>::const_iterator it_m = m_ilinkers.begin(); it_m != m_ilinkers.end(); it_m++) {
            if (it_m->second == linker_type) {
                ECHO(ERRO, "linker type(%d) exist!", linker_type);
                return pipe_pair;
            }
        }
        
        if (rfd <= 0 || wfd <= 0) {
            return pipe_pair;
        }
        
        struct stat rstatbuf, wstatbuf;
        if (fstat(rfd, &rstatbuf) != 0 || fstat(wfd, &wstatbuf) != 0) {
            return pipe_pair;
        }

        if (! S_ISFIFO(rstatbuf.st_mode) || ! S_ISFIFO(wstatbuf.st_mode)) {
            return pipe_pair;
        }

        int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
    
        PipeClient *rpc = new PipeClient(rfd);
        
        rpc->prev_option = op;
        
        rpc->ev.events = op;
        rpc->ev.data.ptr = rpc;
        
        rpc->linker_type = linker_type;
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d) as PIPE read client created.", rpc, rpc->id, rpc->fd);
        
        PipeClient *wpc = new PipeClient(wfd);
        
        wpc->prev_option = op;
        
        wpc->ev.events = op;
        wpc->ev.data.ptr = wpc;
        
        wpc->linker_type = linker_type;
        
        m_heartbeats[linker_type] = now_time();
        
        m_ilinkers[wpc->fd] = wpc->linker_type;
        m_pipe_pairs[linker_type] = std::make_pair(rpc->fd, wpc->fd);
        
        ECHO(INFO, "eclient(%p, id=%d, fd=%d) as PIPE write client created.", wpc, wpc->id, wpc->fd);
        
        pipe_pair = std::make_pair(rpc, wpc);
        
        return pipe_pair;
    }
    void EpollEvHandler::EEH_clear_zombie()
    {
        std::map<pid_t, std::string>::iterator iter_m;
        for (iter_m = m_info_process.begin(); iter_m != m_info_process.end(); iter_m++) {
            int stat_loc;
            pid_t rpid;
            if ((rpid = waitpid(iter_m->first, &stat_loc, WNOHANG)) > 0) {
                if (WIFEXITED(stat_loc)) {
                    ECHO(INFO, "service %s(pid=%d) exited with code %d", 
                            iter_m->second.c_str(), iter_m->first, WEXITSTATUS(stat_loc));
                } else if (WIFSIGNALED(stat_loc)) {
                    ECHO(INFO, "service %s(pid=%d) terminated abnormally with signal %d", 
                            iter_m->second.c_str(), iter_m->first, WTERMSIG(stat_loc));
                }
                if (m_info_process.erase(rpid) == 1) {
                    /** clear sub process success */
                }
            }
        }
    }
    
    void EpollEvHandler::EEH_run()
    {
        struct epoll_event *evs = (struct epoll_event*)calloc(1, sizeof(struct epoll_event) * EPOLL_MAX_NUM);
        if (! evs) {
            return ;
        }

        m_is_running = true;
        
        int read_count = 0;
                
        int i, res;
        while (m_is_running) 
        {
            EEH_clear_zombie();
            
            ECHO(INFO, "epi(%d) waiting: %d cs(%d ls, %d ils, %d ols, %d pps)", 
                m_epi, m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size(), m_pipe_pairs.size());
            res = epoll_wait(m_epi, evs, EPOLL_MAX_NUM, 1000);
            if (res == -1) {
                if (errno != EINTR)
                    return;
                else
                    continue;
            }           
            for (i = 0; i < res; i++)
            {
                int what = evs[i].events;
                
                BaseClient *bc = dynamic_cast<BaseClient*>((BaseClient*)evs[i].data.ptr);
                
                ECHO(INFO, "eclient(%p, id=%d, fd=%d, type=%d, is_server=%d) would do action(%d)",
                                    bc, bc->id, bc->fd, bc->type, bc->is_server, what);

                if (what & (EPOLLHUP|EPOLLERR)) {
                    if (bc->type == EEH_TYPE_TCP || bc->type == EEH_TYPE_PIPE) {
                        /** end of peer closed and there is no need to exist. */
                        bc->action = DO_CLOSE;
                    }
                } else {
                    if (what & EPOLLIN) {
                        if (bc->is_server) {
                            bc->action = DO_ACCEPT;
                        } else {
                            bc->action = DO_READ;
                        }
                    }
                    if (what & EPOLLOUT) {
                        bc->action = DO_WRITE;
                    }
                    if (what & EPOLLRDHUP) {
                        /** close gracefully */
                        bc->action = DO_CLOSE;
                    }
                }
                
                if (bc->action == DO_ACCEPT) {
                    EClient *ec = EEH_TCP_accept(m_clients[bc->fd]);
                    if (ec) {
                        if (EEH_add(ec) != EEH_OK) {
                            ECHO(ERRO, "failed to add eclient");
                        }
                    } else {
                        ECHO(ERRO, "%s:%d accept connect error", bc->host.c_str(), bc->port);
                    }
                } else if (bc->action == DO_READ) {
                    if (bc->read_callback) {
                        bc->read_callback(bc->fd, nullptr, 0, this);
                    }
                } else if (bc->action == DO_WRITE) {
                    if (bc->write_callback) {
                        bc->write_callback(bc->fd, nullptr, 0, this);
                    }
                    EEH_mod(bc, bc->prev_option);
                } else if (bc->action == DO_CLOSE) {
                    if (EEH_del(bc) != EEH_OK) {
                        ECHO(ERRO, "failed to delete eclient(%p)", bc);
                    }
                }
            }
            /** timer call */
            std::map<FD_t, EClient*>::iterator it_m;
            for (it_m = m_clients.begin(); it_m != m_clients.end(); it_m++) {
                BaseClient *bc = dynamic_cast<BaseClient*>(it_m->second);
                if (! bc) {
                    /** maybe it has not enough time to release, continue and wait for a while */
                    continue;
                }
                if (bc->timer_callback) {
                    bc->timer_callback(it_m->second, this);
                }
            }
        }
    }
}