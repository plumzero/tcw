
#include "eemodule.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

ssize_t daemon_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
    
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }

    EEHDBUG(eeh->logger, MODU, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    bool from_outward = false;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        from_outward = true;
    } else {
        from_outward = false;
    }

    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, MODU, "read(%ld): %s", nh, strerror(errno));
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
        EEHERRO(eeh->logger, MODU, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
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
        EEHERRO(eeh->logger, MODU, "crc32 check error");
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicmh(&bich, nullptr);
    bicmh.ExtractHeader(msg.c_str());

    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(msg);
        EEHDBUG(eeh->logger, MODU, "BIC_GUARDRAGON.heartbeat: %lu", bicguard.heartbeat);
        EEHDBUG(eeh->logger, MODU, "BIC_GUARDRAGON.biubiu:    %s",  bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->sid] = now_time();
        return 0;
    }
    
    EEHDBUG(eeh->logger, MODU, "origin=%s, orient=%s, type=%d, from_outward=%d",
                                eeh->m_services_id[bich.origin].c_str(), 
                                eeh->m_services_id[bich.orient].c_str(), bich.type, from_outward);

    decltype (std::declval<std::map<EEHNS::FD_t, EEHNS::SID_t>>().begin()) iterTo;
    if (from_outward) {
        iterTo = std::find_if(eeh->m_ilinkers.begin(), eeh->m_ilinkers.end(),
                                [&bich](decltype(*eeh->m_ilinkers.begin())& ele){
            return ele.second == bich.orient;
        });
    } else {
        iterTo = std::find_if(eeh->m_olinkers.begin(), eeh->m_olinkers.end(),
                                [&bich](decltype(*eeh->m_olinkers.begin())& ele){
            return ele.second == bich.orient;
        });
        if (iterTo == eeh->m_olinkers.end()) {
            EEHINFO(eeh->logger, MODU, "IPC between internal child process");
            iterTo = std::find_if(eeh->m_ilinkers.begin(), eeh->m_ilinkers.end(),
                            [&bich](decltype(*eeh->m_ilinkers.begin())& ele){
                return ele.second == bich.orient;
            });
        }
    }

    if (iterTo->first <= 0) {
        EEHERRO(eeh->logger, MODU, "tofd is 0");
        return -1;
    }

    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[iterTo->first]);
    if (! tobc) {
        return -1;
    }

    /** recover it to the original message(header + BIC_MESSAGE) */
    eeh->m_linker_queues[tobc->sid].emplace(std::string(hbuf, hbuf + sizeof(hbuf)) + msg);

    EEHDBUG(eeh->logger, MODU, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
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
        EEHERRO(eeh->logger, MODU, "an exceptions occurs");
        return -1;
    }
        
    EEHDBUG(eeh->logger, MODU, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                    bc, bc->type, eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());

    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, MODU, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        EEHDBUG(eeh->logger, MODU, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
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

            std::string tomsg;
            tobicm.Serialize(&tomsg);

            std::string tostream;
            if (tomsg.empty()) {
                EEHERRO(eeh->logger, MODU, "msg size is 0");
                return -1;
            }
            add_header(&tostream, tomsg);

            eeh->m_linker_queues[bc->sid].push(tostream);

            EEHDBUG(eeh->logger, MODU, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                        BIC_TYPE_GUARDRAGON, tostream.size(), eeh->m_services_id[tobich.origin].c_str(),
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
    
    EEHDBUG(eeh->logger, MODU, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, MODU, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
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
        EEHERRO(eeh->logger, MODU, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    std::string msg(rbuf, nb);
    if (rbuf) {
        free(rbuf);
    }
    
    EEHDBUG(eeh->logger, MODU, "received msg(len=%lu)", msg.size());

    /** received it and do nothing, instead of passing it to application layer. */
    std::unique_lock<std::mutex> guard(eeh->m_mutex);   /** locked passively */
    eeh->m_messages.push(std::move(msg));
    eeh->m_cond.notify_one();

    EEHDBUG(eeh->logger, MODU, "notified to deal with msg queue(size=%lu)", eeh->m_messages.size());

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
        EEHERRO(eeh->logger, MODU, "an exceptions occurs");
        return -1;
    }
    
    EEHDBUG(eeh->logger, MODU, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                                bc, bc->type,
                                eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());
    
    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, MODU, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        EEHDBUG(eeh->logger, MODU, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
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

        std::string tomsg;
        tobicm.Serialize(&tomsg);

        std::string tostream;
        if (tomsg.empty()) {
            EEHERRO(eeh->logger, MODU, "msg size is 0");
            return -1;
        }
        add_header(&tostream, tomsg);

        eeh->m_linker_queues[bc->sid].push(tostream);

        EEHDBUG(eeh->logger, MODU, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                    BIC_TYPE_GUARDRAGON, tostream.size(), eeh->m_services_id[tobich.origin].c_str(),
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
