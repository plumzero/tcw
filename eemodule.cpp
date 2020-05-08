

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

ssize_t transfer_read_callback(int fd, void *buf, size_t size, void *userp)
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

    std::string bicmsg(rbuf, nb);
    if (rbuf) {
        free(rbuf);
    }

    /** CRC32 check */
    if (crc32calc(bicmsg.c_str(), bicmsg.size()) != ntohl(header.crc32)) {
        EEHERRO(eeh->logger, FLOW, "crc32 check error");
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicmh(&bich, nullptr);
    bicmh.ExtractHeader(bicmsg.c_str());

    BIC_BASE *bicp = nullptr;
    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(bicmsg);
        EEHDBUG(eeh->logger, FLOW, "BIC_GUARDRAGON.heartbeat: %lu", bicguard.heartbeat);
        EEHDBUG(eeh->logger, FLOW, "BIC_GUARDRAGON.biubiu:    %s",  bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->sid] = now_time();
        return 0;
    } else if (bich.type == BIC_TYPE_P2S_SUMMON || bich.type == BIC_TYPE_S2P_SUMMON) {
        bicp = new BIC_SUMMON();
    } else if (bich.type == BIC_TYPE_P2S_MONSTER || bich.type == BIC_TYPE_S2P_MONSTER) {
        bicp = new BIC_MONSTER();
    } else if (bich.type == BIC_TYPE_P2S_BITRON || bich.type == BIC_TYPE_S2P_BITRON) {
        bicp = new BIC_BITRON();
    } else if (bich.type == BIC_TYPE_P2S_BLOCKRON || bich.type == BIC_TYPE_S2P_BLOCKRON) {
        bicp = new BIC_BLOCKRON();
    } else if (bich.type == BIC_TYPE_P2S_BOMBER || bich.type == BIC_TYPE_S2P_BOMBER) {
        bicp = new BIC_BOMBER();
    } else {
        EEHERRO(eeh->logger, FLOW, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }

    BIC_MESSAGE bicmp(nullptr, bicp);
    bicmp.ExtractPayload(bicmsg);
    
    std::string tobicmsg, tomsg;
    BIC_HEADER tobich;
    tobich = BIC_HEADER(bich.origin, bich.orient, bich.type);
    
    EEHDBUG(eeh->logger, FLOW, "origin=%s, orient=%s, type=%d, from_outward=%d",
                                eeh->m_services_id[bich.origin].c_str(), 
                                eeh->m_services_id[bich.orient].c_str(), bich.type, from_outward);

    BIC_MESSAGE tobicm(&tobich, bicp);
    tobicm.Serialize(&tobicmsg);
    
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, FLOW, "msg size is 0");
        return -1;
    }
    add_header(&tomsg, tobicmsg);

    if (bicp != nullptr) {
        delete bicp;
    }

    int tofd = 0;
    if (from_outward) {
        std::map<EEHNS::FD_t, EEHNS::SID_t>::const_iterator it_m;
        for (it_m = eeh->m_ilinkers.begin(); it_m != eeh->m_ilinkers.end(); it_m++) {
            if (it_m->second == bich.orient) {
                tofd = it_m->first;
            }
        }
    } else {
        std::map<EEHNS::FD_t, EEHNS::SID_t>::const_iterator it_m;
        EEHDBUG(eeh->logger, FLOW, "m_olinkers.size=%lu", eeh->m_olinkers.size());
        for (it_m = eeh->m_olinkers.begin(); it_m != eeh->m_olinkers.end(); it_m++) {
            if (it_m->second == bich.orient) {
                tofd = it_m->first;
            }
            EEHDBUG(eeh->logger, FLOW, "fd=%d, sid=%s", it_m->first, eeh->m_services_id[it_m->second].c_str());
        }
    }

    if (tofd <= 0) {
        EEHERRO(eeh->logger, FLOW, "tofd is 0");
        return -1;
    }

    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }

    eeh->m_linker_queues[tobc->sid].push(tomsg);

    EEHDBUG(eeh->logger, FLOW, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                bich.type, tomsg.size(), eeh->m_services_id[bich.origin].c_str(),
                                eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                eeh->m_services_id[bich.orient].c_str());

    eeh->EEH_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

/** do nothing, write purely */
ssize_t transfer_write_callback(int fd, const void *buf, size_t count, void *userp)
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

int transfer_timer_callback(void *args, void *userp)
{   
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;

    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }
    
    return 0;
    
    if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {    /** guard heartbeat */
        if (now_time() - bc->heartbeat >= 1000) {
            bc->heartbeat = now_time();

            BIC_HEADER tobich(eeh->m_id, bc->sid, BIC_TYPE_GUARDRAGON);
            BIC_GUARDRAGON tobicp;
            tobicp.biubiu = "Hello World, 索尼克";
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

ee_event_actions_t transfer_callback_module = {
    transfer_read_callback,
    transfer_write_callback,
    transfer_timer_callback,
};

static int madolche_handle_message(int fd, std::string msg, void *userp)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;

    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
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

    BIC_BASE *tobicp = nullptr;
    BICTYPE totype;
    if (bich.type == BIC_TYPE_P2S_SUMMON) {
        BIC_SUMMON bic;
        BIC_MESSAGE bicsummon(nullptr, &bic);
        
        bicsummon.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.info:  %s", bic.info.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.code:  %lu", bic.code);
        
        BIC_MONSTER* monster = new BIC_MONSTER();
        monster->name = "Madolche Queen Tiaramisu";
        monster->type = "xyz monster (Effect)";
        monster->attribute = "Earth";
        monster->race = "Fairy";
        monster->level = 4;
        monster->attack = 2200;
        monster->defense = 2100;
        monster->description = "魔偶甜点 后冠提拉米苏";
        
        tobicp = monster;
        totype = BIC_TYPE_S2P_MONSTER;
    } else if (bich.type == BIC_TYPE_P2S_BITRON) {
        BIC_BITRON bic;
        BIC_MESSAGE bicbit(nullptr, &bic);
        
        bicbit.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_BITRON.bitslen: %d", bic.bitslen);
        uint32_t i;
        for (i = 0; i < bic.bitslen; ) {
            printf(" %02x", static_cast<int>((unsigned char)bic.bits[i]));
            if (++i % 16 == 0) printf("\n");
        }
        if (i % 16 != 0) printf("\n");
        
        return 0;
    } else if (bich.type == BIC_TYPE_P2S_BLOCKRON) {
        BIC_BLOCKRON bic;
        BIC_MESSAGE bicblock(nullptr, &bic);
        
        bicblock.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_BLOCKRON.fname:     %s", bic.fname.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_BLOCKRON.fsize:     %u", bic.fsize);
        EEHDBUG(eeh->logger, CHLD, "BIC_BLOCKRON.offset:    %u", bic.offset);
        EEHDBUG(eeh->logger, CHLD, "BIC_BLOCKRON.blocksize: %u", bic.blocksize);
        
        std::ofstream ofs;
        std::string ofile(bic.fname + "_bak");
        if (bic.offset == 0) {
            ofs.open(ofile.c_str(), std::ofstream::out | std::ofstream::trunc);
        } else {
            ofs.open(ofile.c_str(), std::ofstream::out | std::ofstream::app);
        }
        
        if (! ofs.is_open()) {
            EEHERRO(eeh->logger, CHLD, "open(\"%s\"): %s", ofile.c_str(), strerror(errno));
            return -1;
        }
        
        ofs.write(bic.block.c_str(), bic.blocksize);
        
        ofs.close();
        
        return 0;
    } else if (bich.type == BIC_TYPE_P2S_BOMBER) {
        BIC_BOMBER bic;
        BIC_MESSAGE bicbomb(nullptr, &bic);
        
        bicbomb.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.service_type: %d", bic.service_type);
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
        
        BIC_BOMBER* bomb = new BIC_BOMBER();
        bomb->service_name = bic.service_name;
        bomb->service_type = bic.service_type;
        bomb->kill = bic.kill;
        bomb->rescode = 1;
        bomb->receipt = "魔偶甜点 将在 1 秒内被吃掉";
        
        signal(SIGALRM, EEHNS::signal_release);
        alarm(2);
        EEHDBUG(eeh->logger, CHLD, "pid %d would be destructed in 2 seconds", getpid());
        
        tobicp = bomb;
        totype = BIC_TYPE_S2P_BOMBER;
    } else {
        EEHERRO(eeh->logger, CHLD, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }
    
    BIC_HEADER tobich(eeh->m_id, bich.origin, totype);
    BIC_MESSAGE tobicm(&tobich, tobicp);
    
    EEHDBUG(eeh->logger, CHLD, "done! msg(type=%d) would send from(%s) to(%s)",
                                totype, eeh->m_services_id[eeh->m_id].c_str(),
                                eeh->m_services_id[bich.origin].c_str());
    
    std::string tobicmsg;
    tobicm.Serialize(&tobicmsg);
    
    std::string tomsg;
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, CHLD, "msg size is 0");
        return -1;
    }
    add_header(&tomsg, tobicmsg);
    
    if (tobicp != nullptr) {
        delete tobicp;
    }
    
    int tofd(0);
    if (eeh->m_pipe_pairs.find(bc->sid) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[bc->sid].second;
    } else {
        EEHERRO(eeh->logger, CHLD, "an exceptions occurs");
        return -1;
    }
    
    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }
        
    eeh->m_linker_queues[tobc->sid].push(tomsg);

    EEHDBUG(eeh->logger, CHLD, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                totype, tomsg.size(), eeh->m_services_id[tobich.origin].c_str(),
                                eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                eeh->m_services_id[tobich.orient].c_str());
        
    eeh->EEH_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}
/** do nothing, read purely */
ssize_t madolche_read_callback(int fd, void *buf, size_t size, void *userp)
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
        EEHERRO(eeh->logger, CHLD, "read(%ld): %s", nh, strerror(errno));
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
    
    int ret = madolche_handle_message(fd, std::string(rbuf, nb), userp);
    if (ret == 0) {
        EEHDBUG(eeh->logger, CHLD, "%s: success handled msg(len=%ld) from ec(%p, t=%d)",
                                    eeh->m_services_id[eeh->m_id].c_str(), nb, bc, bc->type);
    } else {
        EEHERRO(eeh->logger, CHLD, "%s: failure handled msg(len=%ld) from ec(%p, t=%d)",
                                    eeh->m_services_id[eeh->m_id].c_str(), nb, bc, bc->type);
    }
    
    if (rbuf) {
        free(rbuf);
    }
    
    return ret; 
}

/** do nothing, write purely */
ssize_t madolche_write_callback(int fd, const void *buf, size_t count, void *userp)
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

int madolche_timer_callback(void *args, void *userp)
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
        tobicp.biubiu = "Hello World, 魔偶甜点";
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

ee_event_actions_t madolche_callback_module = {
    madolche_read_callback,
    madolche_write_callback,
    madolche_timer_callback,
};

static int gimmickpuppet_handle_message(int fd, std::string msg, void *userp)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;

    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[fd]);
    if (! bc) {
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicm(&bich, nullptr);
    bicm.ExtractHeader(msg);

    if (bc->sid != bich.orient) {
        EEHERRO(eeh->logger, CHLD, "not belong here, discard the message");
        return 0;
    }

    EEHDBUG(eeh->logger, CHLD, "received msg(type=%d, len=%d) from origin(sid=%s) to orient(sid=%s)",
                                bich.type, msg.size(),
                                eeh->m_services_id[bich.origin].c_str(), eeh->m_services_id[bich.orient].c_str());

    BIC_BASE *tobicp = nullptr;
    BICTYPE totype;
    if (bich.type == BIC_TYPE_P2S_SUMMON) {
        BIC_SUMMON bic;
        BIC_MESSAGE bicsummon(nullptr, &bic);
        
        bicsummon.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.info:  %s", bic.info.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_SUMMON.code:  %lu", bic.code);
        
        BIC_MONSTER* monster = new BIC_MONSTER();
        monster->name = "Gimmick Puppet Giant Hunter";
        monster->type = "xyz monster (Effect)";
        monster->attribute = "Dark";
        monster->race = "Machine";
        monster->level = 9;
        monster->attack = 2500;
        monster->defense = 1500;
        monster->description = "机关傀儡-连环杀手";
        
        tobicp = monster;
        totype = BIC_TYPE_S2P_MONSTER;
    } else if (bich.type == BIC_TYPE_P2S_BOMBER) {
        BIC_BOMBER bic;
        BIC_MESSAGE bicbomb(nullptr, &bic);
        
        bicbomb.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.service_type: %d", bic.service_type);
        EEHDBUG(eeh->logger, CHLD, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
        
        BIC_BOMBER* bomb = new BIC_BOMBER();
        bomb->service_name = bic.service_name;
        bomb->service_type = bic.service_type;
        bomb->kill = bic.kill;
        bomb->rescode = 1;
        bomb->receipt = "机关傀儡 将在 2 秒内被摧毁";
        
        signal(SIGALRM, EEHNS::signal_release);
        alarm(2);
        EEHDBUG(eeh->logger, CHLD, "pid %d would be destructed in 2 seconds", getpid());
        
        tobicp = bomb;
        totype = BIC_TYPE_S2P_BOMBER;
    } else {
        EEHERRO(eeh->logger, CHLD, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }
    
    BIC_HEADER tobich(eeh->m_id, bich.origin, totype);
    BIC_MESSAGE tobicm(&tobich, tobicp);
    
    EEHDBUG(eeh->logger, CHLD, "done! msg(type=%d) would send from(%s) to(%s)",
                                totype, eeh->m_services_id[eeh->m_id].c_str(),
                                eeh->m_services_id[bich.origin].c_str());

    std::string tobicmsg;
    tobicm.Serialize(&tobicmsg);
    
    // EEHDBUG(eeh->logger, CHLD, "tobicmsg(%d): %s", tobicmsg.size(), tobicmsg.c_str());
    
    std::string tomsg;
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, CHLD, "msg size is 0");
        return -1;
    }
    add_header(&tomsg, tobicmsg);
    
    if (tobicp != nullptr) {
        delete tobicp;
    }
    
    int tofd(0);
    if (eeh->m_pipe_pairs.find(bc->sid) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[bc->sid].second;
    } else {
        EEHERRO(eeh->logger, CHLD, "an exceptions occurs");
        return -1;
    }
    
    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }
        
    eeh->m_linker_queues[tobc->sid].push(tomsg);

    EEHDBUG(eeh->logger, CHLD, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                totype, tomsg.size(), eeh->m_services_id[tobich.origin].c_str(),
                                eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                eeh->m_services_id[tobich.orient].c_str());
        
    eeh->EEH_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

ssize_t gimmickpuppet_read_callback(int fd, void *buf, size_t size, void *userp)
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
    
    int ret = gimmickpuppet_handle_message(fd, std::string(rbuf, nb), userp);
    if (ret == 0) {
        EEHDBUG(eeh->logger, CHLD, "%s: success handled msg(len=%ld) from ec(%p, t=%d)",
                                    eeh->m_services_id[eeh->m_id].c_str(), nb, bc, bc->type);
    } else {
        EEHERRO(eeh->logger, CHLD, "%s: failure handled msg(len=%ld) from ec(%p, t=%d)",
                                    eeh->m_services_id[eeh->m_id].c_str(), nb, bc, bc->type);
    }
    
    if (rbuf) {
        free(rbuf);
    }
    
    return ret;
}

ssize_t gimmickpuppet_write_callback(int fd, const void *buf, size_t count, void *userp)
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

int gimmickpuppet_timer_callback(void *args, void *userp)
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
        tobicp.biubiu = "Hello World, 机关傀儡";
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

ee_event_actions_t gimmickpuppet_callback_module = {
    gimmickpuppet_read_callback,
    gimmickpuppet_write_callback,
    gimmickpuppet_timer_callback,
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
        
        std::string tobicmsg;
                
        static BICTYPE type = BIC_TYPE_P2S_SUMMON; // BIC_TYPE_NONE;
        
        decltype(eeh->m_services_id.begin()) iterFrom, iterTo;

        iterFrom = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "POLICY"; });
        if (iterFrom == eeh->m_services_id.end()) {
            EEHERRO(eeh->logger, SERV, "could not find service id");
            return -1;
        }

        if (type == BIC_TYPE_P2S_BITRON) {          /** 比特传输 */
        } else if (type == BIC_TYPE_P2S_BLOCKRON) { /** 大文件传输 */
        } else if (type == BIC_TYPE_P2S_BOMBER) {   /** 杀 Madolche */
        } else if (type == BIC_TYPE_P2S_SUMMON) { /** 消息环回 */
            srand(time(nullptr));

            if (rand() % 2) {
                iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "MADOLCHE"; });
                if (iterTo == eeh->m_services_id.end()) {
                    EEHERRO(eeh->logger, SERV, "could not find service id");
                    return -1;
                }
                BIC_HEADER bich(iterFrom->first, iterTo->first, type);
                BIC_SUMMON bicp;
                bicp.info = "召唤信息";
                bicp.sno = "ABYR-JP048";
                bicp.code = 37164373;
                
                BIC_MESSAGE bicm(&bich, &bicp);
                bicm.Serialize(&tobicmsg);
            } else {
                iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "GIMMICK_PUPPET"; });
                if (iterTo == eeh->m_services_id.end()) {
                    EEHERRO(eeh->logger, SERV, "could not find service id");
                    return -1;
                }
                BIC_HEADER bich(iterFrom->first, iterTo->first, type);
                BIC_SUMMON bicp;
                bicp.info = "召唤信息";
                bicp.sno = "PP16-JP010";
                bicp.code = 33776843;
                
                BIC_MESSAGE bicm(&bich, &bicp);
                bicm.Serialize(&tobicmsg);
            }
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