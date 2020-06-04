

#include "eemodule.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

/****************************** 程序员定义和实现 ******************************/

/**
 * 随笔:
 *   1. 禁止使用 static 变量；
 *   2. 子进程使用 exit 退出，进程内启动进程通过 signal 退出；
 *   3. 除了服务回调之外，最好不要再使用其他回调；
 */

ssize_t null_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) fd;
    (void) buf;
    (void) size;
    (void) userp;
    
    return 0;
}

ssize_t null_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) fd;
    (void) buf;
    (void) count;
    (void) userp;
    
    return 0;
}

int null_timer_callback(void *args, void *userp)
{
    (void) args;
    (void) userp;
    
    return 0;
}

ee_event_actions_t null_callback_module = {
    null_read_callback,
    null_write_callback,
    null_timer_callback,
};

ssize_t daemon_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }

    EEHDBUG(eeh->logger, FLOW, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    bool from_outward = false;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        from_outward = true;
    } else {
        from_outward = false;
    }

    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, FLOW, "read(%ld): %s", nh, strerror(errno));
        return -1;
    }

    NegoHeader header;
    memcpy(&header, hbuf, NEGOHSIZE);

    size_t bodysize = ntohs(header.bodysize);

    char *rbuf = (char *)calloc(1, bodysize);
    if (! rbuf) {
        return -1;
    }

    ssize_t nb = read(fd, rbuf, bodysize);
    if (nb != (ssize_t)bodysize) {
        EEHERRO(eeh->logger, FLOW, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }

    std::string msg(rbuf, nb);
    if (rbuf) {
        free(rbuf);
    }

    /** CRC32 check */
    if (crc32calc(msg.c_str(), msg.size()) != ntohl(header.crc32)) {
        EEHERRO(eeh->logger, FLOW, "crc32 check error");
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicmh(&bich, nullptr);
    bicmh.ExtractHeader(msg.c_str());

    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(msg);
        EEHDBUG(eeh->logger, FLOW, "BIC_GUARDRAGON.heartbeat: %lu", bicguard.heartbeat);
        EEHDBUG(eeh->logger, FLOW, "BIC_GUARDRAGON.biubiu:    %s",  bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->sid] = now_time();
        return 0;
    }
    
    EEHDBUG(eeh->logger, FLOW, "origin=%s, orient=%s, type=%d, from_outward=%d",
                                eeh->m_services_id[bich.origin].c_str(), 
                                eeh->m_services_id[bich.orient].c_str(), bich.type, from_outward);

    decltype (std::declval<std::map<EEHNS::FD_t, EEHNS::SID_t>>().begin()) iterTo;
    if (from_outward) {
        iterTo = std::find_if(eeh->m_ilinkers.begin(), eeh->m_ilinkers.end(),
                                [&bich](const decltype(*eeh->m_ilinkers.begin())& ele){
            return ele.second == bich.orient;
        });
    } else {
        iterTo = std::find_if(eeh->m_olinkers.begin(), eeh->m_olinkers.end(),
                                [&bich](const decltype(*eeh->m_olinkers.begin())& ele){
            return ele.second == bich.orient;
        });
    }

    if (iterTo->first <= 0) {
        EEHERRO(eeh->logger, FLOW, "tofd is 0");
        return -1;
    }

    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[iterTo->first]);
    if (! tobc) {
        return -1;
    }

    /** recover it to the original message(header + BIC_MESSAGE) */
    eeh->m_linker_queues[tobc->sid].emplace(std::string(hbuf, hbuf + sizeof(hbuf)) + msg);

    EEHDBUG(eeh->logger, FLOW, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                bich.type, msg.size(), eeh->m_services_id[bich.origin].c_str(),
                                eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                eeh->m_services_id[bich.orient].c_str());

    eeh->EEH_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

/** do nothing, write purely */
ssize_t daemon_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) buf;
    (void) count;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    EEHNS::SID_t sid;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        sid = eeh->m_ilinkers[fd];
    } else if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        sid = eeh->m_olinkers[fd];
    } else {
        EEHERRO(eeh->logger, FLOW, "an exceptions occurs");
        return -1;
    }
        
    EEHDBUG(eeh->logger, FLOW, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                    bc, bc->type, eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());

    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, FLOW, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        EEHDBUG(eeh->logger, CHLD, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int daemon_timer_callback(void *args, void *userp)
{   
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;

    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }
    
    if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {    /** guard heartbeat */
        if (now_time() - bc->heartbeat >= 1000) {
            bc->heartbeat = now_time();

            BIC_HEADER tobich(eeh->m_id, bc->sid, BIC_TYPE_GUARDRAGON);
            BIC_GUARDRAGON tobicp;
            tobicp.biubiu = "Hello World, " + eeh->m_services_id[bc->sid];;
            BIC_MESSAGE tobicm(&tobich, &tobicp);

            std::string tobicmsg;
            tobicm.Serialize(&tobicmsg);

            std::string tomsg;
            if (tobicmsg.empty()) {
                EEHERRO(eeh->logger, FLOW, "msg size is 0");
                return -1;
            }
            add_header(&tomsg, tobicmsg);

            eeh->m_linker_queues[bc->sid].push(tomsg);

            EEHDBUG(eeh->logger, FLOW, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                        BIC_TYPE_GUARDRAGON, tomsg.size(), eeh->m_services_id[tobich.origin].c_str(),
                                        eeh->m_services_id[bc->sid].c_str(), eeh->m_linker_queues[bc->sid].size(),
                                        eeh->m_services_id[tobich.orient].c_str());
            
            eeh->EEH_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
        }
    } else {
        // do nothing
    }
    
    return 0;
}

ee_event_actions_t daemon_callback_module = {
    daemon_read_callback,
    daemon_write_callback,
    daemon_timer_callback,
};

/** do nothing, read purely */
ssize_t child_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    EEHDBUG(eeh->logger, CHLD, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, CHLD, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
        return -1;
    }
    
    NegoHeader header;
    memcpy(&header, hbuf, NEGOHSIZE);
    
    size_t bodysize = ntohs(header.bodysize);
    
    char *rbuf = (char *)calloc(1, bodysize);
    if (! rbuf) {
        return -1;
    }
    
    ssize_t nb = read(fd, rbuf, bodysize);
    if (nb != (ssize_t)bodysize) {
        EEHERRO(eeh->logger, CHLD, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    /** filter the received message simply */
    std::string msg(rbuf, nb);
    if (rbuf) {
        free(rbuf);
    }
    
    BIC_HEADER  bich;
    BIC_MESSAGE bicm(&bich, nullptr);
    bicm.ExtractHeader(msg);
    
    if (bc->sid != bich.orient) {
        EEHERRO(eeh->logger, CHLD, "not belong here, discard the message");
        return 0;
    }

    EEHDBUG(eeh->logger, CHLD, "received msg(type=%d, len=%lu) from origin(sid=%s) to orient(sid=%s)",
                                bich.type, msg.size(),
                                eeh->m_services_id[bich.origin].c_str(), eeh->m_services_id[bich.orient].c_str());

    /** received it and do nothing, instead of passing it to application layer. */
    std::unique_lock<std::mutex> guard(eeh->m_mutex);   /** locked passively */
    eeh->m_messages.push(std::move(msg));
    eeh->m_cond.notify_one();

    EEHDBUG(eeh->logger, CHLD, "notified to deal with msg queue(size=%lu)", eeh->m_messages.size());

    return 0; 
}

/** do nothing, write purely */
ssize_t child_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) buf;
    (void) count;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
        
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    EEHNS::SID_t sid;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        sid = eeh->m_ilinkers[fd];
    } else {
        EEHERRO(eeh->logger, CHLD, "an exceptions occurs");
        return -1;
    }
    
    EEHDBUG(eeh->logger, CHLD, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                                bc, bc->type,
                                eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());
    
    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, CHLD, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        EEHDBUG(eeh->logger, CHLD, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int child_timer_callback(void *args, void *userp)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }

    if (eeh->m_ilinkers.find(bc->fd) != eeh->m_ilinkers.end()) {
        if (now_time() - bc->heartbeat < 1000) {
            return 0;
        }
        bc->heartbeat = now_time();

        BIC_HEADER tobich(eeh->m_id, bc->sid, BIC_TYPE_GUARDRAGON);
        BIC_GUARDRAGON tobicp;
        tobicp.biubiu = "Hello World, " + eeh->m_services_id[bc->sid];
        BIC_MESSAGE tobicm(&tobich, &tobicp);

        std::string tobicmsg;
        tobicm.Serialize(&tobicmsg);

        std::string tomsg;
        if (tobicmsg.empty()) {
            EEHERRO(eeh->logger, CHLD, "msg size is 0");
            return -1;
        }
        add_header(&tomsg, tobicmsg);

        eeh->m_linker_queues[bc->sid].push(tomsg);

        EEHDBUG(eeh->logger, CHLD, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                    BIC_TYPE_GUARDRAGON, tomsg.size(), eeh->m_services_id[tobich.origin].c_str(),
                                    eeh->m_services_id[bc->sid].c_str(), eeh->m_linker_queues[bc->sid].size(),
                                    eeh->m_services_id[tobich.orient].c_str());
        
        eeh->EEH_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
    }

    return 0;
}

ee_event_actions_t child_callback_module = {
    child_read_callback,
    child_write_callback,
    child_timer_callback,
};

ssize_t policy_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    EEHDBUG(eeh->logger, SERV, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, SERV, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
        return -1;
    }
    
    NegoHeader header;
    memcpy(&header, hbuf, NEGOHSIZE);
    
    size_t bodysize = ntohs(header.bodysize);
    
    char *rbuf = (char *)calloc(1, bodysize);
    if (! rbuf) {
        return -1;
    }
    
    ssize_t nb = read(fd, rbuf, bodysize);
    if (nb != (ssize_t)bodysize) {
        EEHERRO(eeh->logger, SERV, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    std::string bicmsg(rbuf, nb);
    
    if (rbuf) {
        free(rbuf);
    }
    
    if (ntohl(header.crc32) != crc32calc(bicmsg.c_str(), bicmsg.size())) {
        return -1;
    }
    
    BIC_HEADER  bich;
    BIC_MESSAGE bicm(&bich, nullptr);
    bicm.ExtractHeader(bicmsg);

    EEHDBUG(eeh->logger, SERV, "received msg(type=%d, len=%lu) from origin(sid=%s) to orient(sid=%s)",
                                bich.type, bicmsg.size(),
                                eeh->m_services_id[bich.origin].c_str(), eeh->m_services_id[bich.orient].c_str());

    if (bc->sid != bich.orient) {
        EEHERRO(eeh->logger, SERV, "not belong here, discard the message");
        return 0;
    }
    
    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(bicmsg);
        EEHDBUG(eeh->logger, SERV, "BIC_GUARDRAGON.heartbeat: %lu", bicguard.heartbeat);
        EEHDBUG(eeh->logger, SERV, "BIC_GUARDRAGON.biubiu:    %s",  bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->sid] = now_time();
    } else if (bich.type == BIC_TYPE_S2P_MONSTER) {
        BIC_MONSTER bicp;
        BIC_MESSAGE bicm(nullptr, &bicp);
        
        bicm.ExtractPayload(bicmsg);
        
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.name:        %s", bicp.name.c_str());
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.type:        %s", bicp.type.c_str());
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.attribute:   %s", bicp.attribute.c_str());
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.race:        %s", bicp.race.c_str());
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.level:       %u", bicp.level);
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.attack:      %u", bicp.attack);
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.defense:     %u", bicp.defense);
        EEHDBUG(eeh->logger, SERV, "BIC_MONSTER.description: %s", bicp.description.c_str());
    } else if (bich.type == BIC_TYPE_S2P_BOMBER) {
        BIC_BOMBER bicp;
        BIC_MESSAGE bicm(nullptr, &bicp);
        
        bicm.ExtractPayload(bicmsg);
        
        EEHDBUG(eeh->logger, SERV, "BIC_BOMBER.service_name: %s", bicp.service_name.c_str());
        EEHDBUG(eeh->logger, SERV, "BIC_BOMBER.service_type: %d", bicp.service_type);
        EEHDBUG(eeh->logger, SERV, "BIC_BOMBER.kill:         %s", bicp.kill ? "true" : "false");
        EEHDBUG(eeh->logger, SERV, "BIC_BOMBER.rescode:      %d", bicp.rescode);
        EEHDBUG(eeh->logger, SERV, "BIC_BOMBER.receipt:      %s", bicp.receipt.c_str());
    } else {
        EEHERRO(eeh->logger, SERV, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }
        
    return 0;
}

ssize_t policy_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) buf;
    (void) count;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
        
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    EEHNS::SID_t sid;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        sid = eeh->m_olinkers[fd];
    } else {
        EEHERRO(eeh->logger, SERV, "an exceptions occurs");
        return -1;
    }
    
    EEHDBUG(eeh->logger, SERV, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                                bc, bc->type,
                                eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());
    
    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, SERV, "write(%lu != %lu): %s", nt, msg.size(), strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();

        EEHDBUG(eeh->logger, SERV, "handled msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int policy_timer_callback(void *args, void *userp)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }

    if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {
        if (now_time() - bc->heartbeat < 1 * 1000) {
            return 0;
        }
        bc->heartbeat = now_time();
        
        srand(time(nullptr));
                
        decltype(eeh->m_services_id.begin()) iterFrom, iterTo;

        iterFrom = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "POLICY"; });
        if (iterFrom == eeh->m_services_id.end()) {
            EEHERRO(eeh->logger, SERV, "could not find service id");
            return -1;
        }
        if (rand() % 2) {
            iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "MADOLCHE"; });
            if (iterTo == eeh->m_services_id.end()) {
                EEHERRO(eeh->logger, SERV, "could not find service id");
                return -1;
            }
        } else {
            iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "GIMMICK_PUPPET"; });
            if (iterTo == eeh->m_services_id.end()) {
                EEHERRO(eeh->logger, SERV, "could not find service id");
                return -1;
            }
        }
        
        static BICTYPE type = BIC_TYPE_P2S_SUMMON;
        std::string tobicmsg;
        static int count = 0;
            
        BIC_HEADER bich(iterFrom->first, iterTo->first, type);
        if (type == BIC_TYPE_P2S_SUMMON) { /** 1. 消息环回 */
            BIC_HEADER bich(iterFrom->first, iterTo->first, type);
            BIC_SUMMON bicp;
            bicp.info = "召唤信息";
            bicp.sno = "ABAB-XYZ8";
            bicp.code = 12345678;
            
            BIC_MESSAGE bicm(&bich, &bicp);
            bicm.Serialize(&tobicmsg);

            if (++count > 5) {
                // type = BIC_TYPE_P2S_BOMBER;
                count = 0;
            }
        } else if (type == BIC_TYPE_P2S_BOMBER) { /** 2. 杀服务测试 */
            BIC_BOMBER bicp;
            bicp.service_name = "销毁 " + eeh->m_services_id[iterTo->first]  + " 服务";
            bicp.service_type = iterTo->first;
            bicp.kill = true;
            
            BIC_MESSAGE bicm(&bich, &bicp);
            bicm.Serialize(&tobicmsg);
            
            type = BIC_TYPE_P2S_BITRON;
        } else if (type == BIC_TYPE_P2S_BITRON) { /** 3. 比特传输 */
            BIC_BITRON bicp;
            unsigned char buf[] = {
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x07, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x09, 0x00, 0x40, 0x00, 0x27, 0x00, 0x26, 0x00,
                0x06, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xf8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x38, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            bicp.bits.assign((char*)buf, sizeof(buf));
            bicp.bitslen = sizeof(buf);
            
            BIC_MESSAGE bicm(&bich, &bicp);
            bicm.Serialize(&tobicmsg);
            
            type = BIC_TYPE_P2S_SUMMON;
        } else {
            return -1;
        }
        
        std::string tomsg;
        
        if (tobicmsg.empty()) {
            EEHERRO(eeh->logger, SERV, "msg size is 0");
            return -1;
        }
        add_header(&tomsg, tobicmsg);
        
        eeh->m_linker_queues[bc->sid].push(tomsg);
        
        EEHDBUG(eeh->logger, SERV, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and send to %s", 
                                    type, tomsg.size(), eeh->m_services_id[iterFrom->first].c_str(),
                                    eeh->m_services_id[bc->sid].c_str(), eeh->m_linker_queues[bc->sid].size(),
                                    eeh->m_services_id[iterTo->first].c_str());
        
        eeh->EEH_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
    }
    
    return 0;
}

ee_event_actions_t policy_callback_module = {
    policy_read_callback,
    policy_write_callback,
    policy_timer_callback,
};