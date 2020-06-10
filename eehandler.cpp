
#include "eehandler.h"
#include "eelog.h"
#include "sha1.h"

/**
 * 随笔:
 *   1. 对稳定信号(signal∈[SIGRTMIN, SIGRTMAX])的屏蔽是没必要的;
 *   2. nginx 对线程池的实现中，没有对 SIGILL, SIGFPE, SIGSEGV, SIGBUS 信号进行屏蔽;
 *   3. 通信端作为服务端时，一般对 SIGPIPE 信号进行屏蔽;
 *   4. 不要对一些结构体(尤其是包含 std::string 成员变量的结构体)使用 memset;
 */

namespace EEHNS {

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
            EpollEvHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGTERM:
            EpollEvHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGINT:
            EpollEvHandler::m_is_running = false;
            break;
        default:
            break;
    }
}
    
std::map<std::string, ee_event_actions_t>           EpollEvHandler::m_linkers_actions{};
std::map<std::string, std::function<void*(void*)>>  EpollEvHandler::m_linkers_func{};

bool EpollEvHandler::m_is_running = false;

EEHErrCode EpollEvHandler::EEH_set_callback(const std::string& service, const ee_event_actions_t& actions)
{
    m_linkers_actions[service] = actions;

    return EEH_OK;
}

EEHErrCode EpollEvHandler::EEH_set_func(const std::string& service, void* func(void*))
{
    m_linkers_func[service] = std::bind(func, std::placeholders::_1);

    return EEH_OK;
}

EEHErrCode EpollEvHandler::EEH_init(const std::string& conf, const std::string& service)
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
        return EEH_ERROR;
    }
    signal(SIGINT, signal_release);
    
    /** [1.1] do some clear */
    m_listeners.clear();
    m_clients.clear();

    /** [2] check conf and service's setting */
    // read conf
    std::ifstream ifs(conf.c_str(), std::ifstream::in | std::ifstream::binary);
    if (! ifs.is_open()) {
        ECHO(ERRO, "open %s: %s", conf.c_str(), strerror(errno));
        return EEH_ERROR;
    }
    ifs >> m_ini;
    ifs.close();
    // check daemon count
    size_t count = std::count_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
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
        return EEH_ERROR;
    }
    // check 'as' option whether illegal or not if have
    auto iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
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
        return EEH_ERROR;
    }
    // check 'listen' key whether non or not if have
    iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
        std::string key, as, listen, section = ele.first;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "listen") listen = m_ini[section][key] | "";
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return ! section.empty() && as == "server" && listen.empty();
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's 'listen' key is non", iterFind->first.c_str());
        return EEH_ERROR;
    }        
    // check 'connect' key whether non or not if have
    iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
        std::string key, as, connect, section = ele.first;
        for (const auto & kv : ele.second) {
            key.clear();
            std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                           [&section](char c) { return tolower((int)c); });
            if (key == "as") as = m_ini[section][key] | "";
            if (key == "connect") connect = m_ini[section][key] | "";
        }
        std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
        return ! section.empty() && as == "client" && connect.empty();
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's 'connect' key is non", iterFind->first.c_str());
        return EEH_ERROR;
    }
    // check each service(`client` not include) which on=yes whether has its corresponding actions
    iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
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
        return ! section.empty() && (as == "daemon" || as == "child" || as == "server") && on
                                 && m_linkers_actions.find(section) == m_linkers_actions.end();
    });
    if (iterFind != m_ini.end()) {
        ECHO(ERRO, "%s's actions is not set", iterFind->first.c_str());
        return EEH_ERROR;
    }
    // find specified service whether exist or not(specified_service="" means as daemon)
    m_is_daemon = false;
    if (specified_service.empty()) {
        iterFind = std::find_if(m_ini.begin(), m_ini.end(), [this](const decltype(*m_ini.begin())& ele) {
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
            return EEH_ERROR;
        }
        specified_service = iterFind->first;
        m_is_daemon = true;
        m_daemon_name = specified_service;
        ECHO(INFO, "daemon service name is %s", specified_service.c_str());
    } else {
        iterFind = std::find_if(m_ini.begin(), m_ini.end(), 
                                [this, &specified_service](const decltype(*m_ini.begin())& ele) {
            std::string key, as, section = ele.first;
            for (const auto & kv : ele.second) {
                key.clear();
                std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                               [&section](char c) { return tolower((int)c); });
                if (key == "as") as = m_ini[section][key] | "";
            }
            std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
            return ! section.empty() && as == "child" && section == specified_service;
        });
        if (iterFind == m_ini.end()) {
            ECHO(ERRO, "could not found %s service as child", specified_service.c_str());
            return EEH_ERROR;
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
        bool hash_id_error{false};
        do {
            uint8_t sha1hash[20]{0};
            SHA1Context sha1_ctx;
            SHA1Init(&sha1_ctx);
            
            if (! hash_id_error) {
                SHA1Update(&sha1_ctx, iterIni->first.c_str(), iterIni->first.size());
            } else {
                std::string strhex = integral2hex(hash_id);
                std::string strbin = hex2bin(strhex);
                SHA1Update(&sha1_ctx, strbin.c_str(), strbin.size());
            }
            SHA1Final(&sha1_ctx, sha1hash);
            
            std::string hex = bin2hex(std::string(sha1hash, sha1hash + sizeof(uint64_t)));
            hash_id = hex2integral<uint64_t>(hex);
            
            if (hash_id < HASH_ID_RESERVE_ZONE) {
                EEHWARN(logger, HAND, "hash_id(%lu) is small than %lu", hash_id, HASH_ID_RESERVE_ZONE);
                hash_id_error = true;
                continue;
            }
            if (m_services_id.find(hash_id) != m_services_id.end()) {
                EEHWARN(logger, HAND, "hash_id(%lu) already exist", hash_id);
                hash_id_error = true;
                continue;
            }
            
            hash_id_error = false;
        } while (hash_id_error);
        
        EEHDBUG(logger, HAND, "section %s's service id is: %lu", iterIni->first.c_str(), hash_id);

        m_services_id[hash_id] = iterIni->first;
        if (iterIni->first == specified_service) {
            m_id = hash_id;
        }
    }
    
    EEHINFO(logger, HAND, "%s's id is %lu", specified_service.c_str(), m_id);
    
    /** [5] create epoll instance */
    m_epi = epoll_create(EPOLL_MAX_NUM);
    if (m_epi < 0) {
        EEHERRO(logger, HAND, "epoll_create: %s", strerror(errno));
        return EEH_ERROR;
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

            EEHINFO(logger, HAND, "deal with section %s", section.c_str());
            
            for (const auto & kv : iterIni->second) {
                key.clear();
                std::transform(kv.first.begin(), kv.first.end(), std::back_inserter(key), 
                               [&section](char c) { return tolower((int)c); });
                if (key == "as") as = m_ini[section][key] | "";
                if (key == "listen" || key == "connect") addr = m_ini[section][key] | "";
                if (key == "on") on = m_ini[section][key] | false;
            }
            EEHDBUG(logger, HAND, "%s's info(as=%s, addr=%s, on=%d)", section.c_str(), as.c_str(), addr.c_str(), on);

            if (! on) {
                continue;
            }
            
            std::transform(as.begin(), as.end(), as.begin(), [](char c) { return tolower((int)c); });
            
            std::string host;
            int port;
            if (as == "server" || as == "client") {
                size_t pos = addr.find(':');
                if (pos == std::string::npos) {
                    EEHERRO(logger, HAND, "%s format error", addr.c_str());
                    return EEH_ERROR;
                }
                host = std::string(addr.begin(), addr.begin() + pos);
                port = std::atoi(std::string(addr.begin() + pos + 1, addr.end()).c_str());
            }

            auto iterId = std::find_if(m_services_id.begin(), m_services_id.end(),
                            [&section](const decltype(*m_services_id.begin())& ele){ return ele.second == section; });
            if (iterId == m_services_id.end()) {
                EEHERRO(logger, HAND, "could not find %s's id", section.c_str());
                return EEH_ERROR;
            }
            EEHDBUG(logger, HAND, "%s's id is %lu", section.c_str(), iterId->first);
            
            if (as == "daemon") {
                // do nothing
            } else if (as == "server") {
                EClient* ec_listen = EEH_TCP_listen(host, port, iterId->first, m_linkers_actions[section]);
                if (! ec_listen) {
                    EEHERRO(logger, HAND, "EEH_TCP_listen failed");
                    return EEH_ERROR;
                }
                if (EEH_add(ec_listen) != EEH_OK) {
                    EEHERRO(logger, HAND, "EEH_add failed");
                    return EEH_ERROR;
                }
                EEHDBUG(logger, HAND, "%s as a %s listened on %s:%d",
                                        section.c_str(), as.c_str(), host.c_str(), port);
            } else if (as == "client") {                    
                EClient* ec_client = EEH_TCP_connect(host, port, iterId->first);
                if (! ec_client) {
                    EEHERRO(logger, HAND, "EEH_TCP_connect failed");
                    return EEH_ERROR;
                }
                if (EEH_add(ec_client) != EEH_OK) {
                    EEHERRO(logger, HAND, "EEH_add failed");
                    return EEH_ERROR;
                }
                dynamic_cast<BaseClient*>(ec_client)->set_actions(m_linkers_actions[m_daemon_name]);
                EEHDBUG(logger, HAND, "%s as a %s connected to %s:%d",
                                        section.c_str(), as.c_str(), host.c_str(), port);
            } else if (as == "child") {
                m_heartbeats[iterId->first] = now_time();
                EEHDBUG(logger, HAND, "%s would as a %s created by daemon", section.c_str(), as.c_str());
            }
        }           
    } else {
        // do nothing
    }

    /** [7] do other init */        
    m_info_process[getpid()] = specified_service;
    m_is_running = false;
    m_conf_name = conf;
    
    EEHINFO(logger, HAND, "eeh initialize success.");
    
    return EEH_OK;
}

void EpollEvHandler::EEH_destroy()
{
    EEHINFO(logger, HAND, "%lu cs(%lu ls, %lu ils, %lu ols) would be destroyed.", 
                    m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size());
    
    m_listeners.clear();
    m_ilinkers.clear();
    m_olinkers.clear();
    m_pipe_pairs.clear();           /** new add */

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
    
    m_linker_queues.clear();        /** new add */
    m_heartbeats.clear();           /** new add */
    m_info_process.clear();
    
    if (m_epi > 0)
        close(m_epi);

    EEHINFO(logger, HAND, "eehandler destroyed.");
    
    delete logger;
    logger = nullptr;
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
        EEHERRO(logger, HAND, "epoll_ctl(EPOLL_CTL_ADD): %s", strerror(errno));
        return EEH_ERROR;
    }
    
    if (m_clients.find(bc->fd) == m_clients.end()) {
        m_clients[bc->fd] = ec;
    }
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, option=%d) add to eehandler.",
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
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d) mod option(%d->%d).",
                                        bc, bc->id, bc->fd, bc->type, bc->ev.events, op);
    
    bc->ev.events = op;
            
    if (epoll_ctl(m_epi, EPOLL_CTL_MOD, bc->fd, &bc->ev) == -1) {
        EEHERRO(logger, HAND, "epoll_ctl(EPOLL_CTL_MOD): %s", strerror(errno));
        return EEH_ERROR;
    }
    
    return EEH_OK;
}

EEHErrCode EpollEvHandler::EEH_del(EClient *ec)
{
    if (! ec)
        return EEH_OK;

    bool exist = false;
    for (auto iter_m = m_clients.begin(); iter_m != m_clients.end(); iter_m++) {
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
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, is_server=%d) delete from eehandler.",
                                                        bc, bc->id, bc->fd, bc->type, bc->is_server);
    
    if (bc->fd <= 0) {
        /** an exception occurs, but do nothing */
    }
        
    if (epoll_ctl(m_epi, EPOLL_CTL_DEL, bc->fd, &bc->ev) == -1) {
        EEHERRO(logger, HAND, "epoll_ctl(EPOLL_CTL_DEL): %s", strerror(errno));
        /** an exception occurs, but do nothing */
    }

    if (bc->type == EEH_TYPE_TCP) {
        if (bc->is_server) {    /** as server */
            for (auto iter_l = bc->clients.begin(); iter_l != bc->clients.end(); iter_l++) {
                BaseClient *bcc = dynamic_cast<BaseClient*>(*iter_l);
                if (bcc) {
                    bcc->sid = ROVER_ID;
                } else {
                    /** an exception occurs, but do nothing */
                }
            }

            if (m_listeners.erase(bc->fd) == 1) {
                // EEHDBUG(logger, HAND, "erase success");
            } else {
                /** an exception occurs, but do nothing */
            }
        } else {    /** as connect client */
            if (bc->sid != ROVER_ID) {
                FD_t sfd = 0;
                for (auto iter_l = m_listeners.begin(); iter_l != m_listeners.end(); iter_l++) {
                    if (iter_l->second == bc->sid) {
                        sfd = iter_l->first;
                        break;
                    }
                }
                if (sfd > 0) {
                    BaseClient *bcs = dynamic_cast<BaseClient*>(m_clients[sfd]);
                    if (! bcs) {
                        EEHERRO(logger, HAND, "unexcepted logical fatal occurred");
                        return EEH_ERROR;
                    }

                    std::list<EClient*>::iterator iter_find = std::find(bcs->clients.begin(), bcs->clients.end(), ec);
                    if (iter_find != bcs->clients.end()) {
                        bcs->clients.erase(iter_find);
                    } else {
                        // EEHDBUG(logger, HAND, "could not find it");
                    }
                } else {
                    EEHINFO(logger, HAND, "eclient(%p, fd=%d) is an active connect client", bc, bc->fd);
                }
            } else {
                // EEHDBUG(logger, HAND, "tcp rover or other client, delete directly");
            }
        }
    } else {
        // EEHDBUG(logger, HAND, "other eeh type");
    }
    
    if (m_ilinkers.erase(bc->fd) == 1) {
        
    } else if (m_olinkers.erase(bc->fd) == 1) { 
    
    } else {
        /** an exception occurs, but do nothing */
    }
    
    if (m_pipe_pairs.erase(bc->sid) == 1) {
        
    } else {
        
    }
    
    if (m_clients.erase(bc->fd) == 1) {
        // EEHDBUG(logger, HAND, "erase success");
    } else {
        /** an exception occurs, but do nothing */
    }       
    if (bc->fd > 0) {
        // EEHDBUG(logger, HAND, "close fd(%d)", bc->fd);
        close(bc->fd);
    } else {
        /** an exception occurs, but do nothing */
    }
    
    delete ec;
    ec = nullptr;
    
    EEHINFO(logger, HAND, "erase success. remain: cs=%lu(ls=%lu, ils=%lu, ols=%lu, pps=%lu)", 
        m_clients.size(), m_listeners.size(), m_ilinkers.size(), m_olinkers.size(), m_pipe_pairs.size());
    
    return EEH_OK;
}

EClient* EpollEvHandler::EEH_TCP_listen(std::string bind_ip, PORT_t service_port, 
                                        SID_t sid, ee_event_actions_t clients_action)
{
    for (auto it_m = m_listeners.begin(); it_m != m_listeners.end(); it_m++) {
        if (it_m->second == sid) {
            /** It's an error return. If it already had, the client should not return with nullptr.
             *  But I think it should not via to here, so just do like this;
             */
            EEHERRO(logger, HAND, "server type(%d) exist!", sid);
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
        EEHERRO(logger, HAND, "getaddrinfo: %s", strerror(errno));
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
        EEHERRO(logger, HAND, "listen(%s:%d): %s", bind_ip.c_str(), service_port, strerror(sys_err));
        
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
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP server(%s:%d) listend.", 
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
        EEHERRO(logger, HAND, "getsockopt(SOL_SOCKET, SO_TYPE): %s", strerror(errno));
        return nullptr;
    }
    
    EEHINFO(logger, HAND, "listener(%p, fd=%d, id=%d, port=%d, prev_option=%d) would accept a connect.",
                            bl, bl->fd, bl->id, bl->port, bl->prev_option);
    
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = (int)sizeof(client_addr);
    int try_times = 10;
    while ((cfd = accept(bl->fd, (struct sockaddr*)&client_addr, &client_addr_len)) == -1) {
        if (errno != EINTR && errno != ECONNABORTED) {
            EEHERRO(logger, HAND, "accept: %s", strerror(errno));
            return nullptr;
        }
        if (try_times-- == 0)
            return nullptr;
    }
    
    int on = 1;
    if (ioctl(cfd, FIONBIO, (const char *)&on) == -1) {
        EEHERRO(logger, HAND, "ioctl(FIONBIO): %s", strerror(errno));
        close(cfd);
        return nullptr;
    }
    
    on = 1;
    if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on)) != 0) {
        EEHERRO(logger, HAND, "setsockopt(IPPROTO_TCP, TCP_NODELAY): %s", strerror(errno));
        close(cfd);
        return nullptr;
    }
    
    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&client_addr, client_addr_len, 
                    hbuf, NI_MAXHOST, sbuf, NI_MAXSERV, NI_NUMERICSERV) != 0) {
        close(cfd);
        EEHERRO(logger, HAND, "getnameinfo: %s", strerror(errno));
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
    
    tc->sid = bl->sid;
    
    tc->set_actions(bl->clients_do);
    
    bl->clients.push_back(tc);
    
    m_olinkers[tc->fd] = tc->sid;
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                    tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
    
    return tc;
}

EClient* EpollEvHandler::EEH_TCP_connect(std::string remote_ip, PORT_t remote_port, SID_t sid)
{
    for (auto it_m = m_olinkers.begin(); it_m != m_olinkers.end(); it_m++) {
        if (it_m->second == sid) {
            /** It's an error return. If it already had, the client should not return with nullptr.
             *  But I think it should not via to here, so just do like this;
             */
            EEHERRO(logger, HAND, "linker type(%lu) exist!", sid);
            return nullptr;
        }
    }
    
    int cfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cfd == -1) {
        EEHERRO(logger, HAND, "socket: %s", strerror(errno));
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
            EEHERRO(logger, HAND, "connect: %s", strerror(errno));
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
        EEHERRO(logger, HAND, "getsockname: %s", strerror(errno));
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
    
    tc->sid = sid;

    m_olinkers[tc->fd] = tc->sid;
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d) as TCP client(%s:%d) connected.", 
                    tc, tc->id, tc->fd, tc->host.c_str(), tc->port);
                    
    return tc;
}

std::pair<EClient*, EClient*> EpollEvHandler::EEH_PIPE_create(FD_t rfd, FD_t wfd, SID_t sid)
{
    std::pair<EClient*, EClient*> pipe_pair(nullptr, nullptr);
    
    for (auto it_m = m_ilinkers.begin(); it_m != m_ilinkers.end(); it_m++) {
        if (it_m->second == sid) {
            EEHERRO(logger, HAND, "linker type(%lu) exist!", sid);
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
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d) as PIPE read client created.", rpc, rpc->id, rpc->fd);
    
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
    
    EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d) as PIPE write client created.", wpc, wpc->id, wpc->fd);
    
    pipe_pair = std::make_pair(rpc, wpc);
    
    return pipe_pair;
}

void EpollEvHandler::EEH_clear_zombie()
{   
    if (! m_is_daemon) {
        return ;
    }
    
    for (auto iter_m = m_info_process.begin(); iter_m != m_info_process.end(); iter_m++) {
        int stat_loc;
        pid_t rpid;
        if ((rpid = waitpid(iter_m->first, &stat_loc, WNOHANG)) > 0) {
            if (WIFEXITED(stat_loc)) {
                EEHINFO(logger, HAND, "service %s(pid=%d) exited with code %d", 
                        iter_m->second.c_str(), iter_m->first, WEXITSTATUS(stat_loc));
            } else if (WIFSIGNALED(stat_loc)) {
                EEHINFO(logger, HAND, "service %s(pid=%d) terminated abnormally with signal %d", 
                        iter_m->second.c_str(), iter_m->first, WTERMSIG(stat_loc));
            }
            if (m_info_process.erase(rpid) == 1) {
                /** clear zombie process success */
            }
        }
    }
}

void EpollEvHandler::EEH_rebuild_child(int rfd, int wfd, 
                                       const std::string& conf,
                                       const std::string& specified_service)
{
    ECHO(INFO, "child process(pid=%d) would run service(%s)",  getpid(), specified_service.c_str());
    
    EpollEvHandler eeh;
    EEHErrCode rescode;
    
    rescode = eeh.EEH_init(conf, specified_service);
    if (rescode != EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return ;
    }
    
    auto iterFind = std::find_if(eeh.m_services_id.begin(), eeh.m_services_id.end(),
                    [&specified_service](const decltype(*eeh.m_services_id.begin())& ele) {
        return ele.second == specified_service;
    });
    if (iterFind == eeh.m_services_id.end()) {
        ECHO(ERRO, "could not find %s's id", specified_service.c_str());
        return ;
    }
    
    SID_t sid = iterFind->first;
    ECHO(INFO, "%s's id is %lu", specified_service.c_str(), sid);

    std::pair<EClient*, EClient*> ec_pipe_pair = eeh.EEH_PIPE_create(rfd, wfd, sid);
    if (! ec_pipe_pair.first) {
        ECHO(ERRO, "EEH_PIPE_create failed");
        return ;
    }
    if (! ec_pipe_pair.second) {
        ECHO(ERRO, "EEH_PIPE_create failed");
        return ;
    }

    dynamic_cast<BaseClient*>(ec_pipe_pair.first)->set_actions(eeh.m_linkers_actions[specified_service]);
    dynamic_cast<BaseClient*>(ec_pipe_pair.second)->set_actions(eeh.m_linkers_actions[specified_service]);
    
    rescode = eeh.EEH_add(ec_pipe_pair.first);
    if (rescode != EEH_OK) {
        ECHO(ERRO, "EEH_add failed");
        return ;
    }
    rescode = eeh.EEH_add(ec_pipe_pair.second);
    if (rescode != EEH_OK) {
        ECHO(ERRO, "EEH_add failed");
        return ;
    }
    
    eeh.m_info_process[getpid()] = specified_service;
    
    if (m_linkers_func.find(specified_service) != m_linkers_func.end()) {
        std::string service{specified_service};
        ECHO(INFO, "service(name=%s, id=%lu) is starting...", specified_service.c_str(), eeh.m_id);
        std::thread th(m_linkers_func[specified_service], &eeh);
        th.detach();
    }
    
    eeh.EEH_run();
    eeh.EEH_destroy();
}

EEHErrCode EpollEvHandler::EEH_guard_child()
{   
    if (! m_is_daemon) {
        return EEH_OK;
    }
        
    for (const auto & ele : m_heartbeats) {
        uint64_t now  = now_time();
        uint64_t last = ele.second;
        SID_t    sid  = ele.first;
        
        if (now - last < 4 * 1000) {
            continue;
        }
        
        EEHINFO(logger, HAND, "would pull up the process (service=%s, sid=%lu)", m_services_id[sid].c_str(), sid);
        int fd_prcw[2];     /** parent read and child write */
        int fd_pwcr[2];     /** parent write and child read */
        pid_t pid;
        
        if (pipe(fd_prcw) < 0) {
            EEHERRO(logger, HAND, "pipe: %s", strerror(errno));
            return EEH_ERROR;
        }
        if (pipe(fd_pwcr) < 0) {
            EEHERRO(logger, HAND, "pipe: %s", strerror(errno));
            if (fd_prcw[0] > 0) close(fd_prcw[0]);
            if (fd_prcw[1] > 0) close(fd_prcw[1]);
            return EEH_ERROR;
        }
        
        pid = fork();
        if (pid < 0) {
            if (fd_prcw[0] > 0) close(fd_prcw[0]);
            if (fd_prcw[1] > 0) close(fd_prcw[1]);
            if (fd_pwcr[0] > 0) close(fd_pwcr[0]);
            if (fd_pwcr[1] > 0) close(fd_pwcr[1]);
            EEHERRO(logger, HAND, "fork: %s", strerror(errno));
            return EEH_ERROR;
        } else if (pid == 0) {
            DBUG("create a new process pid=%d(ppid=%d), now free the old stack", getpid(), getppid());
            std::string conf_name = m_conf_name;
            std::string specified_service = m_services_id[sid];
            
            signal(SIGINT, signal_release);
            sleep(1);
            
            close(fd_prcw[0]);
            close(fd_pwcr[1]);
            
            ECHO(INFO, "would create a new process pid=%d(ppid=%d) as service %s",
                        getpid(), getppid(), specified_service.c_str());
            EEH_rebuild_child(fd_pwcr[0], fd_prcw[1], conf_name, specified_service);
            exit(0);
        } else if (pid > 0) {
            close(fd_prcw[1]);
            close(fd_pwcr[0]);
            std::pair<EClient*, EClient*> ec_pipe_pair = 
                                        EEH_PIPE_create(fd_prcw[0], fd_pwcr[1], sid);
            if (! ec_pipe_pair.first) {
                EEHERRO(logger, HAND, "EEH_PIPE_create failed");
                return EEH_ERROR;
            }
            if (! ec_pipe_pair.second) {
                EEHERRO(logger, HAND, "EEH_PIPE_create failed");
                return EEH_ERROR;
            }
            dynamic_cast<BaseClient*>(ec_pipe_pair.first)->set_actions(m_linkers_actions[m_daemon_name]);
            dynamic_cast<BaseClient*>(ec_pipe_pair.second)->set_actions(m_linkers_actions[m_daemon_name]);
            EEHErrCode rescode;
            rescode = EEH_add(ec_pipe_pair.first);
            if (rescode != EEH_OK) {
                EEHERRO(logger, HAND, "EEH_add failed");
                return EEH_ERROR;
            }
            rescode = EEH_add(ec_pipe_pair.second);
            if (rescode != EEH_OK) {
                EEHERRO(logger, HAND, "EEH_add failed");
                return EEH_ERROR;
            }
            m_info_process[pid] = m_services_id[sid];
        }
    }
    
    return EEH_OK;
}

void EpollEvHandler::EEH_run()
{
    struct epoll_event *evs = (struct epoll_event*)calloc(1, sizeof(struct epoll_event) * EPOLL_MAX_NUM);
    if (! evs) {
        return ;
    }

    m_is_running = true;
                    
    int i, res;
    while (m_is_running) 
    {
        EEH_clear_zombie();
        EEH_guard_child();
        
        EEHINFO(logger, HAND, "epi(%d) waiting: %lu cs(%lu ls, %lu ils, %lu ols, %lu pps)", 
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
            
            EEHINFO(logger, HAND, "eclient(%p, id=%d, fd=%d, t=%d, is_server=%d) would do action(%d)",
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
                        EEHERRO(logger, HAND, "failed to add eclient");
                    }
                } else {
                    EEHERRO(logger, HAND, "%s:%d accept connect error", bc->host.c_str(), bc->port);
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
                    EEHERRO(logger, HAND, "failed to delete eclient(%p)", bc);
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

}
