
#include "eemodule.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

ssize_t daemon_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
        
    tcw::EventHandler *eeh = (tcw::EventHandler *)userp;
    
    tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    Dbug(eeh->logger, MODU, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    bool from_outward = false;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        from_outward = true;
    } else {
        from_outward = false;
    }
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        Erro(eeh->logger, MODU, "read(%ld): %s", nh, strerror(errno));
        return -1;
    }

    NegoHeader header;
    memcpy(&header, hbuf, NEGOHSIZE);

    size_t bodysize = ntohs(header.bodysize);
    if (bodysize == 0) {
        ECHO(DBUG, "====> maybe a heartbeat");
        ECHO(DBUG, "====> header: ver[0]=%c,ver[1]=%c,bodysize=%lu,origin=%lu,orient=%lu", header.ver[0], header.ver[1], bodysize, header.origin, header.orient);
        eeh->m_heartbeats[bc->sid] = now_time();
        return 0;
    }

    ECHO(DBUG, "----> header: ver[0]=%c,ver[1]=%c,bodysize=%lu,origin=%lu,orient=%lu", header.ver[0], header.ver[1], bodysize, header.origin, header.orient);


    char *rbuf = (char *)calloc(1, bodysize);
    if (! rbuf) {
        return -1;
    }

    ssize_t nb = read(fd, rbuf, bodysize);
    if (nb != (ssize_t)bodysize) {
        Erro(eeh->logger, MODU, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
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
        Erro(eeh->logger, MODU, "crc32 check error");
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicmh(&bich, nullptr);
    bicmh.ExtractHeader(msg.c_str());

    ECHO(DBUG, "----> origin=%lu(%s),orient=%lu(%s)", bich.origin, eeh->m_services_id[bich.origin].c_str(), bich.orient, eeh->m_services_id[bich.orient].c_str());

    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(msg);
        Dbug(eeh->logger, MODU, "BIC_GUARDRAGON.heartbeat: %lu", bicguard.heartbeat);
        Dbug(eeh->logger, MODU, "BIC_GUARDRAGON.biubiu:    %s",  bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->sid] = now_time();
        return 0;
    }

    Dbug(eeh->logger, MODU, "origin=%s, orient=%s, from_outward=%d",
                                eeh->m_services_id[bich.origin].c_str(), 
                                eeh->m_services_id[bich.orient].c_str(), from_outward);

    decltype (std::declval<std::map<tcw::FD_t, tcw::SID_t>>().begin()) iterTo;
    int tofd = -1;
    if (from_outward) {
        /** socket connect: recv */
        iterTo = std::find_if(eeh->m_ilinkers.begin(), eeh->m_ilinkers.end(),
                                [&bich](decltype(*eeh->m_ilinkers.begin())& ele){
            return ele.second == bich.orient;
        });
        if (iterTo != eeh->m_ilinkers.end()) {
            tofd = iterTo->first;
            eeh->m_route_fd[bich.origin].insert(fd);
        }
    } else {   
        iterTo = std::find_if(eeh->m_ilinkers.begin(), eeh->m_ilinkers.end(),
                                [&bich](decltype(*eeh->m_ilinkers.begin())& ele){
            return ele.second == bich.orient;
        });
        /** ipc between internal child process */
        if (iterTo != eeh->m_ilinkers.end()) {
            tofd = iterTo->first;
        } else {
            /** socket connect: send  load balance */
            /** load balance */
            if (! eeh->m_route_fd[bich.orient].empty()) {
                size_t idx = rand() % eeh->m_route_fd[bich.orient].size();
                auto itProxy = eeh->m_route_fd[bich.orient].begin();
                for ( ; itProxy != eeh->m_route_fd[bich.orient].end(); itProxy++) {
                    if (idx-- == 0) {
                        break;
                    }
                }
                if (itProxy != eeh->m_route_fd[bich.orient].end()) {
                    tofd = *itProxy;
                }
            } else if (! eeh->m_olinkers.empty()) {
                size_t idx = rand() % eeh->m_olinkers.size();
                for (iterTo = eeh->m_olinkers.begin(); iterTo != eeh->m_olinkers.end(); iterTo++) {
                    if (idx-- == 0) {
                        break;
                    }
                }
                if (iterTo != eeh->m_olinkers.end()) {
                    tofd = iterTo->first;
                    eeh->m_route_fd[bich.orient].insert(tofd);
                }
            }
            if (tofd > 0) {
                std::string smsg = std::string(hbuf, hbuf + sizeof(hbuf)) + msg;
                size_t nt = write(tofd, smsg.c_str(), smsg.size());
                if (nt != smsg.size()) {
                    Erro(eeh->logger, MODU, "write: %s", strerror(errno));
                    return -1;
                }
                
                return 0;
            }
        }
    }

    if (tofd <= 0) {
        /**
         * maybe enter here if peer is closed suddenly while transferring.
         * we tolerate this exception.
         */
        Erro(eeh->logger, MODU, "could not find fd to write");
        return -1;
    }

    tcw::BaseClient *tobc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }
    
    /** recover it to the original message(header + BIC_MESSAGE) */
    eeh->m_linker_queues[tobc->sid].emplace(std::string(hbuf, hbuf + sizeof(hbuf)) + msg);

    Dbug(eeh->logger, MODU, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                bich.type, msg.size(), eeh->m_services_id[bich.origin].c_str(),
                                eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                eeh->m_services_id[bich.orient].c_str());

    eeh->tcw_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

/** do nothing, write purely */
ssize_t daemon_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) buf;
    (void) count;

    tcw::EventHandler *eeh = (tcw::EventHandler *)userp;
    
    tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    tcw::SID_t sid;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        sid = eeh->m_ilinkers[fd];
    } else if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        sid = eeh->m_olinkers[fd];
    } else {
        Erro(eeh->logger, MODU, "an exceptions occurs");
        return -1;
    }
        
    Dbug(eeh->logger, MODU, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                    bc, bc->type, eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());

    while (eeh->m_linker_queues[sid].size() > 0) {
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            Erro(eeh->logger, MODU, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        Dbug(eeh->logger, MODU, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int daemon_timer_callback(void *args, void *userp)
{   
    (void) args;
    (void) userp;

    // tcw::EventHandler *eeh = (tcw::EventHandler *)userp;

    // tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>((tcw::EClient*)args);
    // if (! bc) {
        // return -1;
    // }
    
    // if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {    /** guard heartbeat */
        // if (now_time() - bc->heartbeat >= 1000) {
            // bc->heartbeat = now_time();

            // BIC_HEADER tobich(eeh->m_id, bc->sid, BIC_TYPE_GUARDRAGON);
            // BIC_GUARDRAGON tobicp;
            // tobicp.biubiu = "Hello World, I am " + eeh->m_services_id[eeh->m_id];;
            // BIC_MESSAGE tobicm(&tobich, &tobicp);

            // std::string tomsg;
            // tobicm.Serialize(&tomsg);

            // std::string tostream;
            // if (tomsg.empty()) {
                // Erro(eeh->logger, MODU, "msg size is 0");
                // return -1;
            // }
            // add_header(&tostream, tomsg);

            // eeh->m_linker_queues[bc->sid].push(tostream);
            
            // Dbug(eeh->logger, MODU, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                        // BIC_TYPE_GUARDRAGON, tostream.size(), eeh->m_services_id[tobich.origin].c_str(),
                                        // eeh->m_services_id[bc->sid].c_str(), eeh->m_linker_queues[bc->sid].size(),
                                        // eeh->m_services_id[tobich.orient].c_str());
            
            // eeh->tcw_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
        // }
    // } else {
        // // do nothing
    // }
    
    return 0;
}

event_actions_t daemon_callback_module = {
    daemon_read_callback,
    daemon_write_callback,
    daemon_timer_callback,
};

/** do nothing, read purely */
ssize_t child_read_callback(int fd, void *buf, size_t size, void *userp)
{
    (void) buf;
    (void) size;
    
    tcw::EventHandler *eeh = (tcw::EventHandler *)userp;
    
    tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    Dbug(eeh->logger, MODU, "do read from ec(%p, t=%d, s=%s)", bc, bc->type, eeh->m_services_id[bc->sid].c_str());
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        Erro(eeh->logger, MODU, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
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
        Erro(eeh->logger, MODU, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    std::string msg(rbuf, nb);
    if (rbuf) {
        free(rbuf);
    }
    
    Dbug(eeh->logger, MODU, "received msg(len=%lu)", msg.size());

    /** received it and do nothing, instead of passing it to application layer. */
    std::unique_lock<std::mutex> guard(eeh->m_mutex);   /** locked passively */
    eeh->m_messages.push(std::string(hbuf, hbuf + sizeof(hbuf)) + std::move(msg));
    // eeh->m_messages.push(std::move(msg));
    eeh->m_cond.notify_one();

    Dbug(eeh->logger, MODU, "notified to deal with msg queue(size=%lu)", eeh->m_messages.size());

    return 0; 
}

/** do nothing, write purely */
ssize_t child_write_callback(int fd, const void *buf, size_t count, void *userp)
{
    (void) buf;
    (void) count;
    
    tcw::EventHandler *eeh = (tcw::EventHandler *)userp;
        
    tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }
    
    tcw::SID_t sid;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        sid = eeh->m_ilinkers[fd];
    } else {
        Erro(eeh->logger, MODU, "an exceptions occurs");
        return -1;
    }
    
    Dbug(eeh->logger, MODU, "do write to ec(%p, t=%d, s=%s, queue_size=%lu)", 
                                bc, bc->type,
                                eeh->m_services_id[sid].c_str(), eeh->m_linker_queues[sid].size());
        
    while (eeh->m_linker_queues[sid].size() > 0) {        
        std::string msg(eeh->m_linker_queues[sid].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            Erro(eeh->logger, MODU, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[sid].pop();
        
        Dbug(eeh->logger, MODU, "forwarded msg(len=%lu) to peer end of ec(%p, t=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int child_timer_callback(void *args, void *userp)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)userp;
    tcw::BaseClient *bc = dynamic_cast<tcw::BaseClient*>((tcw::EClient*)args);
    if (! bc) {
        return -1;
    }

    if (eeh->m_ilinkers.find(bc->fd) != eeh->m_ilinkers.end()) {
        if (now_time() - bc->heartbeat < HEART_BEAT_INTERVAL * 1000) {
            return 0;
        }
        bc->heartbeat = now_time();
        
        // BIC_HEADER tobich(eeh->m_id, eeh->m_daemon_id, BIC_TYPE_GUARDRAGON);
        // BIC_GUARDRAGON tobicp;
        // tobicp.biubiu = "Hello World, I am " + eeh->m_services_id[eeh->m_id];
        // BIC_MESSAGE tobicm(&tobich, &tobicp);

        // std::string tomsg;
        // tobicm.Serialize(&tomsg);

        // std::string tostream;
        // if (tomsg.empty()) {
        //     Erro(eeh->logger, MODU, "msg size is 0");
        //     return -1;
        // }

        NegoHeader header;
        
        header.ver[0] = (uint8_t)'h';
        header.ver[1] = (uint8_t)'b';
        header.bodysize = htons(0);
        header.origin = eeh->m_id;
        header.orient = eeh->m_daemon_id;
        header.crc32 = htonl(0);
        
        std::string tostream(std::string((const char *)&header, NEGOHSIZE));

        {
            NegoHeader header_1;
            memset(&header_1, 0, sizeof(header_1));
            header_1.ver[0] = (uint8_t)'h';
            header_1.ver[1] = (uint8_t)'b';
            header_1.bodysize = htons(0);
            header_1.origin = eeh->m_id;
            header_1.orient = eeh->m_daemon_id;

            ECHO(DBUG, "header_1: bodysize=%d,origin=%lu,orient=%lu", header_1.bodysize, header_1.origin, header_1.orient);
        }

        eeh->m_linker_queues[bc->sid].push(tostream);

        // ECHO(DBUG, "bc->sid=%lu", bc->sid);
        // ECHO(DBUG, "tobich.origin=%lu(%s),tobich.orient=%lu(%s)", tobich.origin, eeh->m_services_id[tobich.origin].c_str(), tobich.orient, eeh->m_services_id[tobich.orient].c_str());

        Dbug(eeh->logger, MODU, "pushed msg(len=%lu, from=%s) to que(ownby=%s, size=%lu) and heartbeat to %s", 
                                    tostream.size(), eeh->m_services_id[eeh->m_id].c_str(),
                                    eeh->m_services_id[bc->sid].c_str(), eeh->m_linker_queues[bc->sid].size(),
                                    eeh->m_services_id[eeh->m_daemon_id].c_str());
        
        eeh->tcw_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
    }

    return 0;
}

event_actions_t child_callback_module = {
    child_read_callback,
    child_write_callback,
    child_timer_callback,
};
