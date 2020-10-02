
#include "eehandler.h"
#include "eelog.h"
#include "sha1.h"

namespace tcw {

void signal_exit(int signum)
{
    switch (signum)
    {
        case SIGALRM:
            exit(0);
            // kill(getpid(), SIGKILL); /** violence is not recommended */
            break;
        default:
            break;
    }
}

void signal_release(int signum)
{
    switch (signum)
    {
        case SIGALRM:
            ECHO(INFO, "pid %d release resources", getpid());
            EventHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGTERM:
            EventHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGINT:
            EventHandler::m_is_running = false;
            break;
        default:
            break;
    }
}
    
std::map<std::string, event_actions_t>           EventHandler::m_linkers_actions{};
std::map<std::string, std::function<int(void*)>>  EventHandler::m_linkers_func{};
std::map<std::string, std::function<void(const uint16_t, const uint64_t, uint64_t, const std::string&, void*)>> EventHandler::m_service_callback{};

bool EventHandler::m_is_running = false;

RetCode EventHandler::tcw_register_service(const std::string& service, int func(void*))
{
    m_linkers_func[service] = std::bind(func, std::placeholders::_1);

    return OK;
}

RetCode EventHandler::tcw_register_service_2(const std::string& service, void func(const uint16_t, const uint64_t, const uint64_t, const std::string&, void*))
{
    using namespace std::placeholders;
    m_service_callback[service] = std::bind(func, _1, _2, _3, _4, _5);

    return OK;
}

RetCode EventHandler::tcw_init(const std::string& conf, const std::string& service)
{
    std::string specified_service{service};
    /** [1] signal handler */
    sigset_t set;
    sigemptyset(&set);
    
    int i;
    for (i = SIGRTMIN; i <= SIGRTMAX; i++) {
        sigaddset(&set, i);
    }
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGPIPE);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTTOU);
    sigaddset(&set, SIGTTIN);
    sigaddset(&set, SIGTERM);
    int ret = sigprocmask(SIG_BLOCK, &set, NULL);
    if (ret) {
        ECHO(ERRO, "sigprocmask %s", strerror(errno));
        return ERROR;
    }
    signal(SIGINT, signal_release);
    
    /** [1.1] do some clear */
    m_listeners.clear();
    m_clients.clear();
    m_route_fd.clear();

    /** [2] check conf and service's setting */
    // read conf
    std::ifstream ifs(conf.c_str(), std::ifstream::in | std::ifstream::binary);
    if (! ifs.is_open()) {
        ECHO(ERRO, "open %s: %s", conf.c_str(), strerror(errno));
        return ERROR;
    }
    ifs >> m_ini;
    ifs.close();
    // check daemon count
    size_t count = std::count_if(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
        std::string key, as, section = ele.first;
        bool on;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "on") on = m_ini[section][key] | false;        
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return as == "daemon" && on == true;
    });
    if (count != 1) {
        ECHO(ERRO, "daemon's count(=%lu) is not 1", count);
        return ERROR;
    }
    // check 'as' option whether illegal or not if have
    auto iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
        std::string key, as, section = ele.first;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "as") as = m_ini[section][key] | "";
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return ! section.empty() && as != "daemon" && as != "child" && as != "server" && as != "client";
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's 'as' key illegal", iterFind->first.c_str());
        return ERROR;
    }
    // check 'listen' key whether non or not if have
    iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
        std::string key, as, listen, section = ele.first;
        bool on;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "on") on = m_ini[section][key] | false;
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "listen") listen = m_ini[section][key] | "";
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return ! section.empty() && on && as == "server" && listen.empty();
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's 'listen' key is insufficient", iterFind->first.c_str());
        return ERROR;
    }        
    // check 'connect' key whether non or not if have
    iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
        std::string key, as, connect, serv, section = ele.first;
        bool on;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "on") on = m_ini[section][key] | false;
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "connect") connect = m_ini[section][key] | "";
            if (key == "service") serv = m_ini[section][key] | "";
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return ! section.empty() && on && as == "client" && (connect.empty() || serv.empty());
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's 'connect' key is insufficient", iterFind->first.c_str());
        return ERROR;
    }
    // check each service(`client` not include) which on=yes whether has its corresponding actions
    std::for_each(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
        std::string key, as, section = ele.first;
        bool on;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "on") on = m_ini[section][key] | false;
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        if (as == "daemon" && on) {
            m_linkers_actions[section] = daemon_callback_module;
        } else if (as == "server" && on) {
            m_linkers_actions[section] = child_callback_module;
        } else if (as == "client" && on) {
            m_linkers_actions[section] = daemon_callback_module;
        } else if (as == "child" && on) {
            m_linkers_actions[section] = child_callback_module;
        }
    });
    // find specified service whether exist or not(specified_service="" means as daemon)
    m_is_daemon = false;
    std::string daemon_name;
    if (specified_service.empty()) {
        iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](decltype(*m_ini.begin())& ele) {
            std::string key, as, section = ele.first;
            bool on;
            for (const auto & kv : ele.second) {
                key.clear();
                std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                               [&section](char c) { return tolower((int)c); });
                if (key == "as") as = m_ini[section][key] | "";
                if (key == "on") on = m_ini[section][key] | false;
            }
            std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
            return ! section.empty() && as == "daemon" && on == true;
        });
        if (iterFind == m_ini.end()) {
            ECHO(ERRO, "could not found daemon service");
            return ERROR;
        }
        specified_service = iterFind->first;
        m_is_daemon = true;
        daemon_name = specified_service;
        ECHO(INFO, "daemon service name is %s", specified_service.c_str());
    } else {
        iterFind = std::find_if(m_ini.begin(), m_ini.end(), 
                                [this, &specified_service](decltype(*m_ini.begin())& ele) {
            std::string key, as, section = ele.first;
            for (const auto & kv : ele.second) {
                key.clear();
                std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                               [&section](char c) { return tolower((int)c); });
                if (key == "as") as = m_ini[section][key] | "";
            }
            std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
            return ! section.empty() && (as == "child" || as == "server") && section == specified_service;
        });
        if (iterFind == m_ini.end()) {
            ECHO(ERRO, "could not found %s service as child", specified_service.c_str());
            return ERROR;
        }
        ECHO(INFO, "build service %s as child", specified_service.c_str());
    }
    /** [3] build log */
    std::string logdir = m_ini[""]["LogDir"] | "./";
    uint32_t logsize = m_ini[""]["LogSize"] | (uint32_t)10;
    
    try {
        std::string logname = specified_service + ".log";
        logger = new Logger(logdir.c_str(), logname.c_str(), logsize);
        ECHO(INFO, "process(id=%lu) log file(dir=%s,name=%s,size=%uM) created",
                    (unsigned long)getpid(), logdir.c_str(), logname.c_str(), logsize);
    } catch (std::exception& e) {
        ECHO(ERRO, "an exception caught: %s", e.what());
        logger = new Logger();
    }

    std::string whatlevel = m_ini[""]["LogLevel"] | "INFO";
    std::transform(whatlevel.begin(), whatlevel.end(), whatlevel.begin(), [](char c) {
        return std::toupper((int)c);
    });
    
    int loglevel = whatlevel == "DBUG" ? LOG_LEVEL_DBUG :
                   whatlevel == "INFO" ? LOG_LEVEL_INFO :
                   whatlevel == "WARN" ? LOG_LEVEL_WARN :
                   whatlevel == "ERRO" ? LOG_LEVEL_ERRO : LOG_LEVEL_INFO;

    logger->log_set_global_level(loglevel);
    logger->log_set_level(LOG_TYPE_HAND, loglevel);
    logger->log_set_level(LOG_TYPE_MODU, loglevel);
    logger->log_set_level(LOG_TYPE_FUNC, loglevel);
    logger->log_set_level(LOG_TYPE_TEST, loglevel);

    /** [4] caculate each service's sha1 id */
    decltype(m_ini.begin()) iterIni;
    for (iterIni = m_ini.begin(); iterIni != m_ini.end(); iterIni++) {
        if (iterIni->first.empty()) {
            continue;
        }

        uint64_t hash_id{0};            
        uint8_t sha1hash[20]{0};
        SHA1Context sha1_ctx;
        
        SHA1Init(&sha1_ctx);
        SHA1Update(&sha1_ctx, iterIni->first.c_str(), iterIni->first.size());
        SHA1Final(&sha1_ctx, sha1hash);
        
        std::string hex = bin2hex(std::string(sha1hash, sha1hash + sizeof(uint64_t)));
        hash_id = hex2integral<uint64_t>(hex);
        
        if (m_services_id.find(hash_id) != m_services_id.end()) {
            Warn(logger, HAND, "hash_id(%lu) already exist", hash_id);
            return ERROR;
        }
        
        m_services_id[hash_id] = iterIni->first;
        Info(logger, HAND, "section %s's service id is: %lu", iterIni->first.c_str(), hash_id);

        if (iterIni->first == specified_service) {
            m_id = hash_id;
        }
        if (iterIni->first == daemon_name) {
            m_daemon_id = hash_id;
        }
        
        /** as client ? */
        auto itKV = iterIni->second.find("service");
        if (itKV != iterIni->second.end()) {
            
            SHA1Init(&sha1_ctx);
            SHA1Update(&sha1_ctx, itKV->second.c_str(), itKV->second.size());
            SHA1Final(&sha1_ctx, sha1hash);
        
            hex = bin2hex(std::string(sha1hash, sha1hash + sizeof(uint64_t)));
            hash_id = hex2integral<uint64_t>(hex);

            if (m_services_id.find(hash_id) != m_services_id.end()) {
                Warn(logger, HAND, "hash_id(%lu) already exist", hash_id);
                return ERROR;
            }
            
            m_services_id[hash_id] = itKV->second;
            
            Info(logger, HAND, "server %s's service id is: %lu", itKV->second.c_str(), hash_id);
        }
    }
    
    Info(logger, HAND, "%s's id is %lu(daemon id is %lu)", specified_service.c_str(), m_id, m_daemon_id);
    
    /** [5] create epoll instance */
    m_epi = epoll_create(EPOLL_MAX_NUM);
    if (m_epi < 0) {
        Erro(logger, HAND, "epoll_create: %s", strerror(errno));
        return ERROR;
    }
    
    /** [6] deal with service options */
    if (m_is_daemon) {
        for (iterIni = m_ini.begin(); iterIni != m_ini.end(); iterIni++) {
            if (iterIni->first.empty()) {
                continue;
            }
            
            std::string section, key, as, addr;
            bool on;
            section = iterIni->first;

            Info(logger, HAND, "deal with section %s", section.c_str());
            
            for (const auto & kv : iterIni->second) {
                key.clear();
                std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                               [&section](char c) { return tolower((int)c); });
                if (key == "as") as = m_ini[section][key] | "";
                if (key == "listen" || key == "connect") addr = m_ini[section][key] | "";
                if (key == "on") on = m_ini[section][key] | false;
            }
            Info(logger, HAND, "%s's info(as=%s, addr=%s, on=%d)", section.c_str(), as.c_str(), addr.c_str(), on);

            if (! on) {
                continue;
            }
            
            std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
            
            std::string host;
            int port;
            if (as == "server" || as == "client") {
                size_t pos = addr.find(':');
                if (pos == std::string::npos) {
                    Erro(logger, HAND, "%s format error", addr.c_str());
                    return ERROR;
                }
                host = std::string(addr.begin(), addr.begin() + pos);
                port = std::atoi(std::string(addr.begin() + pos + 1, addr.end()).c_str());
            }

            auto iterId = std::find_if(m_services_id.begin(), m_services_id.end(),
                            [&section](decltype(*m_services_id.begin())& ele){ return ele.second == section; });
            if (iterId == m_services_id.end()) {
                Erro(logger, HAND, "could not find %s's id", section.c_str());
                return ERROR;
            }
            Info(logger, HAND, "%s's id is %lu", section.c_str(), iterId->first);

            if (as == "daemon") {
                // do nothing
            } else if (as == "server") {
                EClient* ec_listen = tcw_tcp_listen(host, port, iterId->first, m_linkers_actions[m_services_id[m_daemon_id]]);
                if (! ec_listen) {
                    Erro(logger, HAND, "tcw_tcp_listen failed");
                    return ERROR;
                }
                if (tcw_add(ec_listen) != OK) {
                    Erro(logger, HAND, "tcw_add failed");
                    return ERROR;
                }
                m_heartbeats[iterId->first] = now_time();
                Info(logger, HAND, "%s as a %s listened on %s:%d", section.c_str(), as.c_str(), host.c_str(), port);
            } else if (as == "client") {
                EClient* ec_client = tcw_tcp_connect(host, port, iterId->first);
                if (! ec_client) {
                    Erro(logger, HAND, "tcw_tcp_connect failed");
                    return ERROR;
                }
                
                if (tcw_add(ec_client) != OK) {
                    Erro(logger, HAND, "tcw_add failed");
                    return ERROR;
                }
                
                dynamic_cast<BaseClient*>(ec_client)->set_actions(m_linkers_actions[m_services_id[m_daemon_id]]);
                Info(logger, HAND, "%s as a %s connected to %s:%d", section.c_str(), as.c_str(), host.c_str(), port);
            } else if (as == "child") {
                m_heartbeats[iterId->first] = now_time();
                Info(logger, HAND, "%s would as a %s created by daemon", section.c_str(), as.c_str());
            }
        }           
    } else {
        // do nothing
    }

    /** [7] do other init */        
    m_info_process[getpid()] = specified_service;
    m_is_running = false;
    m_conf_name = conf;
        
    Info(logger, HAND, "eeh initialize success.");
    
    return OK;
}

void EventHandler::tcw_destroy()
{
    Info(logger, HAND, "%lu cs(%lu ls, %lu ils, %lu ols) would be destroyed.", 
                    m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size());
    
    m_listeners.clear();
    m_ilinkers.clear();
    m_olinkers.clear();
    m_pipe_pairs.clear();
    m_route_fd.clear();
    
    for (auto iter_m = m_clients.begin(); iter_m != m_clients.end(); iter_m++) {
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
    
    m_linker_queues.clear();
    m_heartbeats.clear();
    m_info_process.clear();
    
    if (m_epi > 0)
        close(m_epi);

    Info(logger, HAND, "eehandler destroyed.");
    
    delete logger;
    logger = nullptr;
}

RetCode EventHandler::tcw_add(EClient *ec)
{
    if (! ec)
        return ERROR;
    
    BaseClient *bc = dynamic_cast<BaseClient*>(ec);
    if (! bc)
        return ERROR;
    
    if (bc->fd <= 0)
        return ERROR;
    
    if (epoll_ctl(m_epi, EPOLL_CTL_ADD, bc->fd, &bc->ev) == -1) {
        Erro(logger, HAND, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
        return ERROR;
    }
    
    if (m_clients.find(bc->fd) == m_clients.end()) {
        m_clients[bc->fd] = ec;
    }
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, option=%d) add to eehandler.",
                                        bc, bc->id, bc->fd, bc->type, bc->prev_option);
    
    return OK;
}

RetCode EventHandler::tcw_mod(EClient *ec, OPTION_t op)
{
    if (! ec)
        return ERROR;
    
    BaseClient *bc = dynamic_cast<BaseClient*>(ec);
    if (! bc)
        return ERROR;
    
    if (bc->fd <= 0)
        return ERROR;
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d) mod option(%d->%d).",
                                        bc, bc->id, bc->fd, bc->type, bc->ev.events, op);
    
    bc->ev.events = op;
            
    if (epoll_ctl(m_epi, EPOLL_CTL_MOD, bc->fd, &bc->ev) == -1) {
        Erro(logger, HAND, "epoll_ctl(EPOLL_CTL_MOD): %s", strerror(errno));
        return ERROR;
    }
    
    return OK;
}

RetCode EventHandler::tcw_del(EClient *ec)
{
    if (! ec)
        return OK;

    bool exist = false;
    for (auto iter_m = m_clients.begin(); iter_m != m_clients.end(); iter_m++) {
        if (iter_m->second == ec) {
            exist = true;
            break;
        }
    }
    if (! exist) {
        return OK;
    }
    
    BaseClient *bc = dynamic_cast<BaseClient*>(ec);
    if (! bc)
        return OK;
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, is_server=%d) delete from eehandler.",
                                                        bc, bc->id, bc->fd, bc->type, bc->is_server);
    
    if (bc->fd <= 0) {
        /** an exception occurs, but do nothing */
    }
        
    if (epoll_ctl(m_epi, EPOLL_CTL_DEL, bc->fd, &bc->ev) == -1) {
        Erro(logger, HAND, "epoll_ctl(EPOLL_CTL_DEL): %s", strerror(errno));
        /** an exception occurs, but do nothing */
    }

    if (bc->type == TYPE_TCP) {
        if (bc->is_server) {    /** as server */
            for (auto iter_l = bc->clients.begin(); iter_l != bc->clients.end(); iter_l++) {
                BaseClient *bcc = dynamic_cast<BaseClient*>(*iter_l);
                if (bcc) {
                    /** do nothing */
                } else {
                    /** an exception occurs, but do nothing */
                }
            }

            if (m_listeners.erase(bc->fd) == 1) {
                // Dbug(logger, HAND, "erase success");
            } else {
                /** an exception occurs, but do nothing */
            }
        } else {    /** as connect client */
            /** do nothing */
        }
    } else {
        // Dbug(logger, HAND, "other eeh type");
    }
    
    if (m_ilinkers.erase(bc->fd) == 1) {
        
    } else if (m_olinkers.erase(bc->fd) == 1) { 
    
    } else {
        /** an exception occurs, but do nothing */
    }
    
    for (auto & ele : m_route_fd) {
        if (ele.second.erase(bc->fd) == 1) {

        } else {
            /** an exception occurs, but do nothing */
        }
    }

    if (m_pipe_pairs.erase(bc->sid) == 1) {
        
    } else {
        
    }
    
    if (m_clients.erase(bc->fd) == 1) {
        // Dbug(logger, HAND, "erase success");
    } else {
        /** an exception occurs, but do nothing */
    }       
    if (bc->fd > 0) {
        // Dbug(logger, HAND, "close fd(%d)", bc->fd);
        close(bc->fd);
    } else {
        /** an exception occurs, but do nothing */
    }
    
    delete ec;
    ec = nullptr;
    
    Info(logger, HAND, "erase success. remain: cs=%lu(ls=%lu, ils=%lu, ols=%lu, pps=%lu)", 
        m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size(), m_pipe_pairs.size());
    
    return OK;
}

EClient* EventHandler::tcw_tcp_listen(std::string bind_ip, PORT_t service_port, 
                                        SID_t sid, event_actions_t clients_action)
{
    for (auto it_m = m_listeners.begin(); it_m != m_listeners.end(); it_m++) {
        if (it_m->second == sid) {
            /** It's an error return. If it already had, the client should not return with nullptr.
             *  But I think it should not via to here, so just do like this;
             */
            Erro(logger, HAND, "server type(%d) exist!", sid);
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
        Erro(logger, HAND, "getaddrinfo: %s", strerror(errno));
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
        Erro(logger, HAND, "listen(%s:%d): %s", bind_ip.c_str(), service_port, strerror(sys_err));
        
        freeaddrinfo(addr_list);
        return nullptr;
    }
    
    freeaddrinfo(addr_list);
    
    BaseClient *tc = new TcpClient(lfd, bind_ip, service_port, true);
    if (! tc)
        return nullptr;
    
    int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
    
    tc->prev_option = op;
    tc->sid = sid;
    
    tc->ev.events = op;
    tc->ev.data.ptr = tc;
    
    tc->is_server = true;
    tc->clients_do = clients_action;
    m_listeners[tc->fd] = sid;
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP server(%s:%d) listend.", 
                        tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
    
    return tc;
}

EClient* EventHandler::tcw_tcp_accept(EListener *el)
{
    if (! el)
        return nullptr;

    BaseClient *bl = dynamic_cast<BaseClient*>(el);
    
    int cfd = -1;
    int type;
    socklen_t type_len = (int)sizeof(type);
    
    if (getsockopt(bl->fd, SOL_SOCKET, SO_TYPE, (void*)&type, &type_len) != 0 || 
        (type != SOCK_STREAM)) {
        Erro(logger, HAND, "getsockopt(SOL_SOCKET, SO_TYPE): %s", strerror(errno));
        return nullptr;
    }

    Info(logger, HAND, "listener(%p, fd=%d, id=%d, port=%d, prev_option=%d) would accept a connect.",
                            bl, bl->fd, bl->id, bl->port, bl->prev_option);
    
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = (int)sizeof(client_addr);
    int try_times = 10;
    while ((cfd = accept(bl->fd, (struct sockaddr*)&client_addr, &client_addr_len)) == -1) {
        if (errno != EINTR && errno != ECONNABORTED) {
            Erro(logger, HAND, "accept: %s", strerror(errno));
            return nullptr;
        }
        if (try_times-- == 0)
            return nullptr;
    }

    int on = 1;
    if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on)) != 0) {
        Erro(logger, HAND, "setsockopt(IPPROTO_TCP, TCP_NODELAY): %s", strerror(errno));
        close(cfd);
        return nullptr;
    }

    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&client_addr, client_addr_len, 
                    hbuf, NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICSERV) != 0) {
        close(cfd);
        Erro(logger, HAND, "getnameinfo: %s", strerror(errno));
        return nullptr;
    }

    char buf[NEGOHSIZE];
    ssize_t nh = read(cfd, buf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        Erro(logger, HAND, "read 'NegoHeader' failed(ret=%ld)", nh);
        return nullptr;
    }
    
    SID_t csid;
    NegoHeader header;
    memcpy(&header, buf, NEGOHSIZE);
    if (header.ver[0] == (uint8_t)'w' && header.ver[1] == (uint8_t)'s') {
        csid = header.pholder;
    } else {
        Erro(logger, HAND, "certain unexcepted error occured");
        return nullptr;
    }
    
    if (m_services_id.find(csid) != m_services_id.end()) {
        Erro(logger, HAND, "already exist sid=%lu as service=%s", csid, m_services_id[csid].c_str());
        return nullptr;
    }
    
    memset(&header, 0, NEGOHSIZE);
    header.ver[0] = (uint8_t)'o';
    header.ver[1] = (uint8_t)'k';
    header.bodysize = 0;
    header.pholder = bl->sid;
        
    nh = write(cfd, &header, NEGOHSIZE);
    if (nh != sizeof(NegoHeader)) {
        Erro(logger, HAND, "write 'NegoHeader' failed(ret=%d)", nh);
        return nullptr;
    }
        
    Info(logger, HAND, "tcp server finished to deal with the connection with remote client(sid=%lu)", csid);
    ECHO(INFO, "tcp server finished to deal with the connection with remote client(fd=%d, sid=%lu)", cfd, csid);
    
    on = 1;
    if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
        Erro(logger, HAND, "ioctl(FIONBIO): %s", strerror(errno));
        close(cfd);
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
    
    tc->sid = csid;
    
    tc->set_actions(bl->clients_do);
    
    bl->clients.push_back(tc);
    
    m_olinkers[tc->fd] = tc->sid;
    
    m_linker_queues.insert(std::make_pair(tc->sid, std::queue<std::string>()));
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                    tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
    
    return tc;
}

EClient* EventHandler::tcw_tcp_connect(std::string remote_ip, PORT_t remote_port, SID_t sid)
{
    for (auto it_m = m_olinkers.begin(); it_m != m_olinkers.end(); it_m++) {
        if (it_m->second == sid) {
            /** It's an error return. If it already had, the client should not return with nullptr.
             *  But I think it should not via to here, so just do like this;
             */
            Erro(logger, HAND, "linker type(%lu) exist!", sid);
            return nullptr;
        }
    }

    int cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cfd == -1) {
        Erro(logger, HAND, "socket: %s", strerror(errno));
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
            Erro(logger, HAND, "connect: %s", strerror(errno));
            close(cfd);         /// 后面添加一个 m_errcode, eeh 不背锅
            return nullptr;
        }
        if (try_times-- == 0)
            return nullptr;
    }

    int on = 1;
    if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on)) != 0) {
        Erro(logger, HAND, "setsockopt(IPPROTO_TCP, TCP_NODELAY): %s", strerror(errno));
        close(cfd);
        return nullptr;
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    if (getsockname(cfd, (struct sockaddr*)&client_addr, &client_addr_len) != 0) {
        Erro(logger, HAND, "getsockname: %s", strerror(errno));
        close(cfd);
        return nullptr;
    }
    
    NegoHeader header;
    memset(&header, 0, NEGOHSIZE);
    header.ver[0] = (uint8_t)'w';
    header.ver[1] = (uint8_t)'s';
    header.bodysize = 0;
    header.pholder = sid;
        
    ssize_t nh = write(cfd, &header, NEGOHSIZE);
    if (nh != sizeof(NegoHeader)) {
        Erro(logger, HAND, "write 'NegoHeader' failed(ret=%ld)", nh);
        return nullptr;
    }
        
    char buf[NEGOHSIZE];
    nh = read(cfd, buf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        Erro(logger, HAND, "read 'NegoHeader' failed(ret=%ld)", nh);
        return nullptr;
    }
    
    memcpy(&header, buf, NEGOHSIZE);
    if (header.ver[0] == (uint8_t)'o' && header.ver[1] == (uint8_t)'k') {
        /** do nothing */
    } else {
        Erro(logger, HAND, "certain unexcepted error occured");
        return nullptr;
    }
    
    on = 1;
    if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
        close(cfd);
        return nullptr;
    }
    
    Info(logger, HAND, "tcp client finished to deal with connecting to remote service(fd=%d, sid=%lu)", cfd, header.pholder);
    ECHO(INFO, "tcp client finished to deal with connecting to remote service(fd=%d, sid=%lu)", cfd, header.pholder);
    
    BaseClient *tc = new TcpClient(cfd, remote_ip, remote_port);
    if (! tc)
        return nullptr;
    
    int op = EPOLLIN | EPOLLHUP | EPOLLRDHUP;

    tc->prev_option = op;
    
    tc->host = inet_ntoa(client_addr.sin_addr);
    tc->port = ntohs(client_addr.sin_port);
    
    tc->ev.events = op;
    tc->ev.data.ptr = tc;
    
    tc->sid = sid;

    m_olinkers[tc->fd] = tc->sid;
    
    m_linker_queues.insert(std::make_pair(tc->sid, std::queue<std::string>()));
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                    tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
                    
    return tc;
}

std::pair<EClient*, EClient*> EventHandler::tcw_pipe_create(FD_t rfd, FD_t wfd, SID_t sid)
{
    std::pair<EClient*, EClient*> pipe_pair(nullptr, nullptr);
    
    for (auto it_m = m_ilinkers.begin(); it_m != m_ilinkers.end(); it_m++) {
        if (it_m->second == sid) {
            Erro(logger, HAND, "linker type(%lu) exist!", sid);
            /** It's an error return. If it already had, the pipe_pair should not return with nullptr.
             *  But I think it should not via to here, so just do like this;
             */
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
    
    rpc->sid = sid;
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d) as PIPE read client created.", rpc, rpc->id, rpc->fd);
    
    PipeClient *wpc = new PipeClient(wfd);
    
    wpc->prev_option = op;
    
    wpc->ev.events = op;
    wpc->ev.data.ptr = wpc;
    
    wpc->sid = sid;
    
    if (m_is_daemon) {
        m_heartbeats[sid] = now_time();
    }
    
    m_ilinkers[wpc->fd] = wpc->sid;
    m_pipe_pairs[sid] = std::make_pair(rpc->fd, wpc->fd);
    
    m_linker_queues.insert(std::make_pair(sid, std::queue<std::string>()));
    
    Info(logger, HAND, "eclient(%p, id=%d, fd=%d) as PIPE write client created.", wpc, wpc->id, wpc->fd);
    
    pipe_pair = std::make_pair(rpc, wpc);
    
    return pipe_pair;
}

void EventHandler::tcw_clear_zombie()
{   
    if (! m_is_daemon) {
        return ;
    }
    
    for (auto iter_m = m_info_process.begin(); iter_m != m_info_process.end(); iter_m++) {
        int stat_loc;
        pid_t rpid;
        if ((rpid = waitpid(iter_m->first, &stat_loc, WNOHANG)) > 0) {
            if (WIFEXITED(stat_loc)) {
                Info(logger, HAND, "service %s(pid=%d) exited with code %d", 
                        iter_m->second.c_str(), iter_m->first, WEXITSTATUS(stat_loc));
            } else if (WIFSIGNALED(stat_loc)) {
                Info(logger, HAND, "service %s(pid=%d) terminated abnormally with signal %d", 
                        iter_m->second.c_str(), iter_m->first, WTERMSIG(stat_loc));
            }
            if (m_info_process.erase(rpid) == 1) {
                /** clear zombie process success */
            }
        }
    }
}

void EventHandler::tcw_rebuild_child(int rfd, int wfd, 
                                       const std::string& conf,
                                       const std::string& specified_service,
                                       const SID_t daemon_id)
{
    ECHO(INFO, "child process(pid=%d) would run service(%s)",  getpid(), specified_service.c_str());
    
    EventHandler eeh;
    RetCode rescode;
    
    rescode = eeh.tcw_init(conf, specified_service);
    if (rescode != OK) {
        ECHO(ERRO, "tcw_init failed");
        return ;
    }
    
    eeh.m_daemon_id = daemon_id;
    
    auto iterFind = std::find_if(eeh.m_services_id.begin(), eeh.m_services_id.end(),
                    [&specified_service](decltype(*eeh.m_services_id.begin())& ele) {
        return ele.second == specified_service;
    });
    if (iterFind == eeh.m_services_id.end()) {
        ECHO(ERRO, "could not find %s's id", specified_service.c_str());
        return ;
    }
    
    SID_t sid = iterFind->first;
    ECHO(INFO, "%s's id is %lu", specified_service.c_str(), sid);

    std::pair<EClient*, EClient*> ec_pipe_pair = eeh.tcw_pipe_create(rfd, wfd, sid);
    if (! ec_pipe_pair.first) {
        ECHO(ERRO, "tcw_pipe_create failed");
        return ;
    }
    if (! ec_pipe_pair.second) {
        ECHO(ERRO, "tcw_pipe_create failed");
        return ;
    }

    dynamic_cast<BaseClient*>(ec_pipe_pair.first)->set_actions(eeh.m_linkers_actions[specified_service]);
    dynamic_cast<BaseClient*>(ec_pipe_pair.second)->set_actions(eeh.m_linkers_actions[specified_service]);
    
    rescode = eeh.tcw_add(ec_pipe_pair.first);
    if (rescode != OK) {
        ECHO(ERRO, "tcw_add failed");
        return ;
    }
    rescode = eeh.tcw_add(ec_pipe_pair.second);
    if (rescode != OK) {
        ECHO(ERRO, "tcw_add failed");
        return ;
    }
    
    eeh.m_info_process[getpid()] = specified_service;
    
    // if (m_linkers_func.find(specified_service) != m_linkers_func.end()) {
    //     std::string service{specified_service};
    //     ECHO(INFO, "service(name=%s, id=%lu) is starting...", specified_service.c_str(), eeh.m_id);
    //     std::thread th(m_linkers_func[specified_service], &eeh);
    //     th.detach();
    // }

    if (m_service_callback.find(specified_service) != m_service_callback.end()) {
        std::string service{specified_service};
        ECHO(INFO, "service(name=%s, id=%lu) is starting...", specified_service.c_str(), eeh.m_id);
        std::thread th([&eeh, specified_service](){
            while (true) {
                /** wait for the message to deal with */
                std::unique_lock<std::mutex> guard(eeh.m_mutex);
                if (! eeh.m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh.m_messages.empty(); })) {
                    Dbug(eeh.logger, HAND, "thread msg queue is empty");
                    continue;
                }
                Dbug(eeh.logger, HAND, "deal with thread msg queue(size=%lu)", eeh.m_messages.size());
                
                std::string stream = std::move(eeh.m_messages.front());
                eeh.m_messages.pop();
                guard.unlock();

                uint16_t msgid = 0;
                uint64_t origin = 0;
                uint64_t orient = 0;
                std::string msg;
                if (eeh.tcw_check_message(stream, &msgid, &origin, &orient, &msg) != OK) {
                    Erro(eeh.logger, HAND, "err msg(stream.size=%lu,msgid=%u,origin=%lu,orient=%lu,msg.size=%lu)",
                                            stream.size(), msgid, origin, orient, msg.size());
                    continue;
                }
                m_service_callback[specified_service](msgid, origin, orient, msg, &eeh);
            }
        });
        th.detach();
    }
    
    eeh.tcw_run();
    eeh.tcw_destroy();
}

RetCode EventHandler::tcw_guard_child()
{   
    if (! m_is_daemon) {
        return OK;
    }
        
    for (const auto & ele : m_heartbeats) {
        uint64_t now  = now_time();
        uint64_t last = ele.second;
        SID_t    sid  = ele.first;

        if (m_hb_offline.find(sid) == m_hb_offline.end()) {
            m_hb_offline[sid] = BitRing<HEART_BEAT_OFFLINE>();
        }

        uint64_t interval = (HEART_BEAT_INTERVAL * 1.3) * 1000;
        if (now - last > interval) {
            m_hb_offline[sid].set();
        } else {
            m_hb_offline[sid].unset();
        }
        
        if (m_hb_offline[sid].ratio() < 0.99) {
            continue;
        }
        
        Info(logger, HAND, "would pull up the process (service=%s, sid=%lu)", m_services_id[sid].c_str(), sid);
        int fd_prcw[2];     /** parent read and child write */
        int fd_pwcr[2];     /** parent write and child read */
        pid_t pid;
        
        if (pipe(fd_prcw) < 0) {
            Erro(logger, HAND, "pipe: %s", strerror(errno));
            return ERROR;
        }
        if (pipe(fd_pwcr) < 0) {
            Erro(logger, HAND, "pipe: %s", strerror(errno));
            if (fd_prcw[0] > 0) close(fd_prcw[0]);
            if (fd_prcw[1] > 0) close(fd_prcw[1]);
            return ERROR;
        }
        
        pid = fork();
        if (pid < 0) {
            if (fd_prcw[0] > 0) close(fd_prcw[0]);
            if (fd_prcw[1] > 0) close(fd_prcw[1]);
            if (fd_pwcr[0] > 0) close(fd_pwcr[0]);
            if (fd_pwcr[1] > 0) close(fd_pwcr[1]);
            Erro(logger, HAND, "fork: %s", strerror(errno));
            return ERROR;
        } else if (pid == 0) {
            ECHO(INFO, "create a new process pid=%d(ppid=%d), now free the old stack", getpid(), getppid());
            std::string conf_name = m_conf_name;
            std::string specified_service = m_services_id[sid];
            SID_t daemon_id = m_daemon_id;
            
            signal(SIGINT, signal_release);
            sleep(1);
            
            close(fd_prcw[0]);
            close(fd_pwcr[1]);
            
            ECHO(INFO, "would create a new process pid=%d(ppid=%d) as service %s",
                        getpid(), getppid(), specified_service.c_str());
            tcw_rebuild_child(fd_pwcr[0], fd_prcw[1], conf_name, specified_service, daemon_id);
            exit(0);
        } else if (pid > 0) {
            close(fd_prcw[1]);
            close(fd_pwcr[0]);
            std::pair<EClient*, EClient*> ec_pipe_pair = 
                                        tcw_pipe_create(fd_prcw[0], fd_pwcr[1], sid);
            if (! ec_pipe_pair.first) {
                Erro(logger, HAND, "tcw_pipe_create failed");
                return ERROR;
            }
            if (! ec_pipe_pair.second) {
                Erro(logger, HAND, "tcw_pipe_create failed");
                return ERROR;
            }
            dynamic_cast<BaseClient*>(ec_pipe_pair.first)->set_actions(m_linkers_actions[m_services_id[m_daemon_id]]);
            dynamic_cast<BaseClient*>(ec_pipe_pair.second)->set_actions(m_linkers_actions[m_services_id[m_daemon_id]]);
            RetCode rescode;
            rescode = tcw_add(ec_pipe_pair.first);
            if (rescode != OK) {
                Erro(logger, HAND, "tcw_add failed");
                return ERROR;
            }
            rescode = tcw_add(ec_pipe_pair.second);
            if (rescode != OK) {
                Erro(logger, HAND, "tcw_add failed");
                return ERROR;
            }
            m_info_process[pid] = m_services_id[sid];
        }
    }
    
    return OK;
}

void EventHandler::tcw_run()
{
    m_is_running = true;

    if (m_is_daemon) {
        std::thread guard_and_clear([this](){
            while (m_is_running) {
                tcw_clear_zombie();
                tcw_guard_child();

                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        guard_and_clear.detach();
    }

    struct epoll_event *evs = (struct epoll_event*)calloc(1, sizeof(struct epoll_event) * EPOLL_MAX_NUM);
    if (! evs) {
        return ;
    }
                   
    int i, res;
    while (m_is_running) 
    {        
        Info(logger, HAND, "epi(%d) waiting: %lu cs(%lu ls, %lu ils, %lu ols, %lu pps)", 
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
            
            Info(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, is_server=%d) would do action(%d)",
                                bc, bc->id, bc->fd, bc->type, bc->is_server, what);

            if (what & (EPOLLHUP|EPOLLERR)) {
                if (bc->type == TYPE_TCP || bc->type == TYPE_PIPE) {
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
                EClient *ec = tcw_tcp_accept(m_clients[bc->fd]);
                if (ec) {
                    if (tcw_add(ec) != OK) {
                        Erro(logger, HAND, "failed to add eclient");
                    }
                } else {
                    Erro(logger, HAND, "%s:%d accept connect error", bc->host.c_str(), bc->port);
                }
            } else if (bc->action == DO_READ) {
                if (bc->read_callback) {
                    bc->read_callback(bc->fd, nullptr, 0, this);
                }
            } else if (bc->action == DO_WRITE) {
                if (bc->write_callback) {
                    bc->write_callback(bc->fd, nullptr, 0, this);
                }
                tcw_mod(bc, bc->prev_option);
            } else if (bc->action == DO_CLOSE) {
                if (tcw_del(bc) != OK) {
                    Erro(logger, HAND, "failed to delete eclient(%p)", bc);
                }
            }
        }
        /** timer call */
        for (auto it_m = m_clients.begin(); it_m != m_clients.end(); it_m++) {
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
    
    if (evs) free(evs);
}

RetCode EventHandler::tcw_check_message(const std::string& stream, uint16_t* msgid, uint64_t* origin, uint64_t* orient, std::string* msg)
{
    if (stream.size() <= sizeof(NegoHeader)) {
        return ERROR;
    }

    NegoHeader header;
    memcpy(&header, stream.c_str(), sizeof(NegoHeader));

    if (m_id != header.orient) {
        return ERROR;
    }

    *msgid = ntohs(header.msgid);
    *origin = header.origin;
    *orient = header.orient;

    size_t bodysize = ntohs(header.bodysize);

    msg->assign(stream.c_str() + sizeof(NegoHeader), bodysize);

    return OK;
}

RetCode EventHandler::tcw_send_message(const uint16_t msgid, const uint64_t tosid, const std::string& msg)
{
    std::string tostream;

    if (tosid == 0) {
        Erro(logger, HAND, "tosid(%lu) is illegal", tosid);
        return ERROR;
    }
    add_header(&tostream, msgid, m_id, tosid, msg);

    int tofd = 0;
    if (m_id != m_daemon_id) {
        if (m_pipe_pairs.find(m_id) != m_pipe_pairs.end()) {
            tofd = m_pipe_pairs[m_id].second;
        } else {
            Erro(logger, HAND, "pipe pair not found");
            return ERROR;
        }
    } else {
        auto iterIn = std::find_if(m_ilinkers.begin(), m_ilinkers.end(), [&tosid](decltype(*m_ilinkers.begin())& ele){ return ele.second == tosid; });
        if (iterIn != m_ilinkers.end()) {
            tofd = iterIn->first;
        } else {
            auto iterOut = std::find_if(m_olinkers.begin(), m_olinkers.end(), [&tosid](decltype(*m_olinkers.begin())& ele){ return ele.second == tosid; });
            if (iterOut != m_olinkers.end()) {
                tofd = iterOut->first;
            } else {
                Erro(logger, HAND, "this exception deserves an attention");
            }
        }
    }

    tcw::BaseClient* tobc = dynamic_cast<tcw::BaseClient*>(m_clients[tofd]);
    if (! tobc) {
        Erro(logger, HAND, "could not find the client");
        return ERROR;
    }

    m_linker_queues[tobc->sid].push(tostream);

    tcw_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return OK;
}

uint64_t EventHandler::tcw_get_sid(const std::string& service)
{
    auto iterTo = std::find_if(m_services_id.begin(), m_services_id.end(),
            [service](decltype(*m_services_id.begin())& ele){ return ele.second == service; });
    if (iterTo == m_services_id.end()) {
        return 0;
    } else {
        return iterTo->first;
    }
}

}
