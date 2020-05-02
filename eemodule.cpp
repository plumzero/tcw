

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
 */

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
            EEHNS::EpollEvHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGTERM:
            EEHNS::EpollEvHandler::m_is_running = false;
            signal(SIGALRM, signal_exit);
            alarm(1);
            break;
        case SIGINT:
            EEHNS::EpollEvHandler::m_is_running = false;
            break;
        default:
            break;
    }
}

void rebuild_child_process_service(int rfd, int wfd, EEHNS::SID_t linker_type)
{   
    ECHO(INFO, "child process(pid=%d) would run service(%s)", 
                        getpid(), "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    eeh.EEH_init(linker_type);
    std::pair<EEHNS::EClient*, EEHNS::EClient*> ec_pipe_pair = 
                eeh.EEH_PIPE_create(rfd, wfd, linker_type);
    if (! ec_pipe_pair.first) {
        ECHO(ERRO, "EEH_PIPE_create failed");
        return ;
    }
    if (! ec_pipe_pair.second) {
        ECHO(ERRO, "EEH_PIPE_create failed");
        return ;
    }
    dynamic_cast<EEHNS::BaseClient*>(ec_pipe_pair.first)->set_actions(eeh.m_linkers_map[linker_type].second);
    dynamic_cast<EEHNS::BaseClient*>(ec_pipe_pair.second)->set_actions(eeh.m_linkers_map[linker_type].second);
    rescode = eeh.EEH_add(ec_pipe_pair.first);
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_add failed");
        return ;
    }
    rescode = eeh.EEH_add(ec_pipe_pair.second);
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_add failed");
        return ;
    }
    
    eeh.m_info_process[getpid()] = 
                eeh.m_linkers_map[linker_type].first;
    
    eeh.EEH_run();
    eeh.EEH_destroy();
}

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

    EEHINFO(eeh->logger, TRAN, "do read from eclient(%p, type=%d)", bc, bc->type);
    bool from_outward = false;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        from_outward = true;
    } else {
        from_outward = false;
    }

    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, TRAN, "read(%ld): %s", nh, strerror(errno));
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
        EEHERRO(eeh->logger, TRAN, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
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
        EEHERRO(eeh->logger, TRAN, "crc32 check error");
        return -1;
    }

    BIC_HEADER  bich;
    BIC_MESSAGE bicmh(&bich, nullptr);
    bicmh.ExtractHeader(bicmsg.c_str());

    // 删除
    // if (from_outward) {
        // if (bich.origin != LINKER_TYPE_POLICY) {
            // EEHERRO(eeh->logger, TRAN, "danger! illegal policy!");
            // return -1;
        // }
    // }

    BIC_BASE *bicp = nullptr;
    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(bicmsg);
        EEHDBUG(eeh->logger, TRAN, "BIC_GUARDRAGON.heartbeat: %ld", bicguard.heartbeat);
        EEHDBUG(eeh->logger, TRAN, "BIC_GUARDRAGON.biubiu:    %s", bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->linker_type] = now_time();
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
        EEHERRO(eeh->logger, TRAN, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }

    BIC_MESSAGE bicmp(nullptr, bicp);
    bicmp.ExtractPayload(bicmsg);
    
    std::string tobicmsg, tomsg;
    BIC_HEADER tobich;
    if (from_outward) {
        tobich = BIC_HEADER(bich.origin, bich.orient, bich.type);
    } else {
        tobich = BIC_HEADER(eeh->m_type, bich.orient, bich.type);
    }

    BIC_MESSAGE tobicm(&tobich, bicp);
    tobicm.Serialize(&tobicmsg);
    
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, TRAN, "msg size is 0");
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
        for (it_m = eeh->m_olinkers.begin(); it_m != eeh->m_olinkers.end(); it_m++) {
            if (it_m->second == bich.orient) {
                tofd = it_m->first;
            }
        }
    }

    if (tofd <= 0) {
        return -1;
    }

    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }

    eeh->m_linker_queues[tobc->linker_type].push(tomsg);

    EEHINFO(eeh->logger, TRAN, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and forward to eclient(%p, type=%d)", 
                tomsg.size(), tobc->linker_type, eeh->m_linker_queues[tobc->linker_type].size(), tobc, tobc->type);

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
    
    EEHNS::SID_t linker_type;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        linker_type = eeh->m_ilinkers[fd];
    } else if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        linker_type = eeh->m_olinkers[fd];
    } else {
        EEHERRO(eeh->logger, TRAN, "an exceptions occurs");
        return -1;
    }
        
    EEHINFO(eeh->logger, TRAN, "do write to eclient(%p, type=%d, linker_type=%d, queue_size=%lu)", 
                    bc, bc->type, linker_type, eeh->m_linker_queues[linker_type].size());

    while (eeh->m_linker_queues[linker_type].size() > 0) {
        std::string msg(eeh->m_linker_queues[linker_type].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, TRAN, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[linker_type].pop();
        EEHINFO(eeh->logger, TRAN, "transfered msg(len=%lu) to peer end of eclient(%p, type=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

int transfer_timer_callback(void *args, void *userp)
{   
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    
    if (eeh->m_type != SERVER_TYPE_TRANSFER) {
        return -1;
    }
    
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }
    
    std::map<EEHNS::SID_t, uint64_t>::iterator it_m;
    for (it_m = eeh->m_heartbeats.begin(); it_m != eeh->m_heartbeats.end(); it_m++) {
        if (now_time() - it_m->second > 4 * 1000) {
            if (eeh->m_info_process[getpid()] != eeh->m_linkers_map[SERVER_TYPE_TRANSFER].first) {
                return -1;
            }
            
            bool logical_error = false;
            std::map<EEHNS::FD_t, EEHNS::SID_t>::iterator iter_m;
            for (iter_m = eeh->m_ilinkers.begin(); iter_m != eeh->m_ilinkers.end(); iter_m++) {
                if (iter_m->second == it_m->first) {
                    logical_error = true;
                }
            }
            if (logical_error) {
                EEHERRO(eeh->logger, TRAN, "============= a logical error occurs =============");
                return -1;
            } else {
                EEHDBUG(eeh->logger, TRAN, "============================ 重新拉起进程 ======================= pid");
                int fd_prcw[2];     /** parent read and child write */
                int fd_pwcr[2];     /** parent write and child read */
                pid_t pid;
                
                if (pipe(fd_prcw) < 0) {
                    EEHERRO(eeh->logger, TRAN, "pipe: %s", strerror(errno));
                    return -1;
                }
                if (pipe(fd_pwcr) < 0) {
                    EEHERRO(eeh->logger, TRAN, "pipe: %s", strerror(errno));
                    if (fd_prcw[0] > 0) close(fd_prcw[0]);
                    if (fd_prcw[1] > 0) close(fd_prcw[1]);
                    return -1;
                }
                
                pid = fork();
                if (pid < 0) {
                    if (fd_prcw[0] > 0) close(fd_prcw[0]);
                    if (fd_prcw[1] > 0) close(fd_prcw[1]);
                    if (fd_pwcr[0] > 0) close(fd_pwcr[0]);
                    if (fd_pwcr[1] > 0) close(fd_pwcr[1]);
                    EEHERRO(eeh->logger, TRAN, "fork: %s", strerror(errno));
                    return -1;
                } else if (pid == 0) {
                    ECHO(INFO, "create a new process pid=%d(ppid=%d)", getpid(), getppid());
                    EEHNS::SID_t linker_type = it_m->first;
                    
                    signal(SIGINT, signal_release);
                    sleep(1);
                    
                    close(fd_prcw[0]);
                    close(fd_pwcr[1]);
                    
                    rebuild_child_process_service(fd_pwcr[0], fd_prcw[1], linker_type);
                    exit(0);
                } else if (pid > 0) {
                    close(fd_prcw[1]);
                    close(fd_pwcr[0]);
                    std::pair<EEHNS::EClient*, EEHNS::EClient*> ec_pipe_pair = 
                                eeh->EEH_PIPE_create(fd_prcw[0], fd_pwcr[1], it_m->first);
                    if (! ec_pipe_pair.first) {
                        EEHERRO(eeh->logger, TRAN, "EEH_PIPE_create failed");
                        return -1;
                    }
                    if (! ec_pipe_pair.second) {
                        EEHERRO(eeh->logger, TRAN, "EEH_PIPE_create failed");
                        return -1;
                    }
                    dynamic_cast<EEHNS::BaseClient*>(ec_pipe_pair.first)->set_actions(transfer_callback_module);
                    dynamic_cast<EEHNS::BaseClient*>(ec_pipe_pair.second)->set_actions(transfer_callback_module);
                    EEHNS::EEHErrCode rescode;
                    rescode = eeh->EEH_add(ec_pipe_pair.first);
                    if (rescode != EEHNS::EEH_OK) {
                        EEHERRO(eeh->logger, TRAN, "EEH_add failed");
                        return -1;
                    }
                    rescode = eeh->EEH_add(ec_pipe_pair.second);
                    if (rescode != EEHNS::EEH_OK) {
                        EEHERRO(eeh->logger, TRAN, "EEH_add failed");
                        return -1;
                    }
                    eeh->m_info_process[pid] = eeh->m_linkers_map[it_m->first].first;
                }
            }
        }
    }
    
    if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {    /** guard heartbeat */
        if (now_time() - bc->heartbeat >= 1000) {
            bc->heartbeat = now_time();

            BIC_HEADER tobich(eeh->m_type, bc->linker_type, BIC_TYPE_GUARDRAGON);
            BIC_GUARDRAGON tobicp;
            tobicp.biubiu = "Hello World, Transfer";
            BIC_MESSAGE tobicm(&tobich, &tobicp);

            std::string tobicmsg;
            tobicm.Serialize(&tobicmsg);

            std::string tomsg;
            if (tobicmsg.empty()) {
                EEHERRO(eeh->logger, TRAN, "msg size is 0");
                return -1;
            }
            add_header(&tomsg, tobicmsg);

            eeh->m_linker_queues[bc->linker_type].push(tomsg);

            EEHINFO(eeh->logger, TRAN, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and heartbeat to eclient(%p, type=%d)", 
                    tomsg.size(), bc->linker_type, eeh->m_linker_queues[bc->linker_type].size(), bc, bc->type);
            
            eeh->EEH_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
        }
    } else {

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

    if (bc->linker_type != bich.orient) {
        EEHERRO(eeh->logger, MADO, "not belong here, discard the message");
        return 0;
    }

    EEHINFO(eeh->logger, MADO, "received msg(len=%lu, type=%d) from origin(linker=%d) to orient(linker=%d)",
                                                        msg.size(), bich.type, bich.origin, bich.orient);

    BIC_BASE *tobicp = nullptr;
    BICTYPE totype;
    if (bich.type == BIC_TYPE_P2S_SUMMON) {
        BIC_SUMMON bic;
        BIC_MESSAGE bicsummon(nullptr, &bic);
        
        bicsummon.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, MADO, "BIC_SUMMON.info:  %s", bic.info.c_str());
        EEHDBUG(eeh->logger, MADO, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
        EEHDBUG(eeh->logger, MADO, "BIC_SUMMON.code:  %lu", bic.code);
        
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
        
        EEHDBUG(eeh->logger, MADO, "BIC_BITRON.bitslen: %d", bic.bitslen);
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
        
        EEHDBUG(eeh->logger, MADO, "BIC_BLOCKRON.fname:     %s", bic.fname.c_str());
        EEHDBUG(eeh->logger, MADO, "BIC_BLOCKRON.fsize:     %u", bic.fsize);
        EEHDBUG(eeh->logger, MADO, "BIC_BLOCKRON.offset:    %u", bic.offset);
        EEHDBUG(eeh->logger, MADO, "BIC_BLOCKRON.blocksize: %u", bic.blocksize);
        
        std::ofstream ofs;
        std::string ofile(bic.fname + "_bak");
        if (bic.offset == 0) {
            ofs.open(ofile.c_str(), std::ofstream::out | std::ofstream::trunc);
        } else {
            ofs.open(ofile.c_str(), std::ofstream::out | std::ofstream::app);
        }
        
        if (! ofs.is_open()) {
            EEHERRO(eeh->logger, MADO, "open(\"%s\"): %s", ofile.c_str(), strerror(errno));
            return -1;
        }
        
        ofs.write(bic.block.c_str(), bic.blocksize);
        
        ofs.close();
        
        return 0;
    } else if (bich.type == BIC_TYPE_P2S_BOMBER) {
        BIC_BOMBER bic;
        BIC_MESSAGE bicbomb(nullptr, &bic);
        
        bicbomb.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, MADO, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
        EEHDBUG(eeh->logger, MADO, "BIC_BOMBER.service_type: %d", bic.service_type);
        EEHDBUG(eeh->logger, MADO, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
        
        BIC_BOMBER* bomb = new BIC_BOMBER();
        bomb->service_name = bic.service_name;
        bomb->service_type = bic.service_type;
        bomb->kill = bic.kill;
        bomb->rescode = 1;
        bomb->receipt = "魔偶甜点 将在 1 秒内被吃掉";
        
        signal(SIGALRM, signal_release);
        alarm(2);
        EEHINFO(eeh->logger, MADO, "pid %d would be destructed in 2 seconds", getpid());
        
        tobicp = bomb;
        totype = BIC_TYPE_S2P_BOMBER;
    } else {
        EEHERRO(eeh->logger, MADO, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }
    
    BIC_HEADER tobich(eeh->m_type, bich.origin, totype);
    BIC_MESSAGE tobicm(&tobich, tobicp);
    
    std::string tobicmsg;
    tobicm.Serialize(&tobicmsg);
    
    std::string tomsg;
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, MADO, "msg size is 0");
        return -1;
    }
    add_header(&tomsg, tobicmsg);
    
    if (tobicp != nullptr) {
        delete tobicp;
    }
    
    int tofd(0);
    if (eeh->m_pipe_pairs.find(bc->linker_type) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[bc->linker_type].second;
    } else {
        EEHERRO(eeh->logger, MADO, "an exceptions occurs");
        return -1;
    }
    
    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }
        
    eeh->m_linker_queues[tobc->linker_type].push(tomsg);

    EEHINFO(eeh->logger, MADO, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and forward to eclient(%p, type=%d)", 
            tomsg.size(), tobc->linker_type, eeh->m_linker_queues[tobc->linker_type].size(), tobc, tobc->type);
        
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
    
    EEHINFO(eeh->logger, MADO, "do read from eclient(%p, type=%d)", bc, bc->type);
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, MADO, "read(%ld): %s", nh, strerror(errno));
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
        EEHERRO(eeh->logger, MADO, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    int ret = madolche_handle_message(fd, std::string(rbuf, nb), userp);
    if (ret == 0) {
        EEHINFO(eeh->logger, MADO, "Madolche: success handled msg(len=%ld) from eclient(%p, type=%d)", nb, bc, bc->type);
    } else {
        EEHERRO(eeh->logger, MADO, "Madolche: failure handled msg(len=%ld) from eclient(%p, type=%d)", nb, bc, bc->type);
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
    
    EEHNS::SID_t linker_type;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        linker_type = eeh->m_ilinkers[fd];
    } else {
        EEHERRO(eeh->logger, MADO, "an exceptions occurs");
        return -1;
    }
    
    EEHINFO(eeh->logger, MADO, "do write to eclient(%p, type=%d, linker_type=%d, queue_size=%lu)", 
                    bc, bc->type, linker_type, eeh->m_linker_queues[linker_type].size());
    
    while (eeh->m_linker_queues[linker_type].size() > 0) {
        std::string msg(eeh->m_linker_queues[linker_type].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, MADO, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[linker_type].pop();
        EEHINFO(eeh->logger, MADO, "transfered msg(len=%lu) to peer end of eclient(%p, type=%d)", nt, bc, bc->type);
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

        BIC_HEADER tobich(eeh->m_type, bc->linker_type, BIC_TYPE_GUARDRAGON);
        BIC_GUARDRAGON tobicp;
        tobicp.biubiu = "Hello World, 魔偶甜点";
        BIC_MESSAGE tobicm(&tobich, &tobicp);

        std::string tobicmsg;
        tobicm.Serialize(&tobicmsg);

        std::string tomsg;
        if (tobicmsg.empty()) {
            EEHERRO(eeh->logger, MADO, "msg size is 0");
            return -1;
        }
        add_header(&tomsg, tobicmsg);

        eeh->m_linker_queues[bc->linker_type].push(tomsg);

        EEHINFO(eeh->logger, MADO, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and heartbeat to eclient(%p, type=%d)", 
                tomsg.size(), bc->linker_type, eeh->m_linker_queues[bc->linker_type].size(), bc, bc->type);
        
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

    if (bc->linker_type != bich.orient) {
        EEHERRO(eeh->logger, GIMM, "not belong here, discard the message");
        return 0;
    }

    EEHINFO(eeh->logger, GIMM, "received msg(len=%lu, type=%d) from origin(linker=%d) to orient(linker=%d)",
                                                        msg.size(), bich.type, bich.origin, bich.orient);

    BIC_BASE *tobicp = nullptr;
    BICTYPE totype;
    if (bich.type == BIC_TYPE_P2S_SUMMON) {
        BIC_SUMMON bic;
        BIC_MESSAGE bicsummon(nullptr, &bic);
        
        bicsummon.ExtractPayload(msg);
        
        EEHDBUG(eeh->logger, GIMM, "BIC_SUMMON.info:  %s", bic.info.c_str());
        EEHDBUG(eeh->logger, GIMM, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
        EEHDBUG(eeh->logger, GIMM, "BIC_SUMMON.code:  %lu", bic.code);
        
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
        
        EEHDBUG(eeh->logger, GIMM, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
        EEHDBUG(eeh->logger, GIMM, "BIC_BOMBER.service_type: %d", bic.service_type);
        EEHDBUG(eeh->logger, GIMM, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
        
        BIC_BOMBER* bomb = new BIC_BOMBER();
        bomb->service_name = bic.service_name;
        bomb->service_type = bic.service_type;
        bomb->kill = bic.kill;
        bomb->rescode = 1;
        bomb->receipt = "机关傀儡 将在 2 秒内被摧毁";
        
        signal(SIGALRM, signal_release);
        alarm(2);
        EEHINFO(eeh->logger, GIMM, "pid %d would be destructed in 2 seconds", getpid());
        
        tobicp = bomb;
        totype = BIC_TYPE_S2P_BOMBER;
    } else {
        EEHERRO(eeh->logger, GIMM, "undefined or unhandled msg(%d)", (int)bich.type);
        return -1;
    }
    
    BIC_HEADER tobich(eeh->m_type, bich.origin, totype);
    BIC_MESSAGE tobicm(&tobich, tobicp);
    
    EEHDBUG(eeh->logger, GIMM, "===> m_type=%d, bich.origin=%d, totype=%d", eeh->m_type, bich.origin, totype);
    
    std::string tobicmsg;
    tobicm.Serialize(&tobicmsg);
    
    // EEHDBUG(eeh->logger, GIMM, "tobicmsg(%d): %s", tobicmsg.size(), tobicmsg.c_str());
    
    std::string tomsg;
    if (tobicmsg.empty()) {
        EEHERRO(eeh->logger, GIMM, "msg size is 0");
        return -1;
    }
    add_header(&tomsg, tobicmsg);
    
    if (tobicp != nullptr) {
        delete tobicp;
    }
    
    int tofd(0);
    if (eeh->m_pipe_pairs.find(bc->linker_type) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[bc->linker_type].second;
    } else {
        EEHERRO(eeh->logger, GIMM, "an exceptions occurs");
        return -1;
    }
    
    EEHNS::BaseClient *tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        return -1;
    }
        
    eeh->m_linker_queues[tobc->linker_type].push(tomsg);

    EEHINFO(eeh->logger, GIMM, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and forward to eclient(%p, type=%d)", 
            tomsg.size(), tobc->linker_type, eeh->m_linker_queues[tobc->linker_type].size(), tobc, tobc->type);
        
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
    
    EEHINFO(eeh->logger, GIMM, "do read from eclient(%p, type=%d)", bc, bc->type);
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, GIMM, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
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
        EEHERRO(eeh->logger, GIMM, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
        if (rbuf) {
            free(rbuf);
        }
        return -1;
    }
    
    int ret = gimmickpuppet_handle_message(fd, std::string(rbuf, nb), userp);
    if (ret == 0) {
        EEHINFO(eeh->logger, GIMM, "GimmickPuppet: success handled msg(len=%ld) from eclient(%p, type=%d)", nb, bc, bc->type);
    } else {
        EEHERRO(eeh->logger, GIMM, "GimmickPuppet: failure handled msg(len=%ld) from eclient(%p, type=%d)", nb, bc, bc->type);
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
    
    EEHNS::SID_t linker_type;
    if (eeh->m_ilinkers.find(fd) != eeh->m_ilinkers.end()) {
        linker_type = eeh->m_ilinkers[fd];
    } else {
        EEHERRO(eeh->logger, GIMM, "an exceptions occurs");
        return -1;
    }
    
    EEHINFO(eeh->logger, GIMM, "do write to eclient(%p, type=%d, linker_type=%d, queue_size=%lu)", 
                    bc, bc->type, linker_type, eeh->m_linker_queues[linker_type].size());
    
    while (eeh->m_linker_queues[linker_type].size() > 0) {
        std::string msg(eeh->m_linker_queues[linker_type].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, GIMM, "write: %s", strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[linker_type].pop();
        EEHINFO(eeh->logger, GIMM, "transfered msg(len=%lu) to peer end of eclient(%p, type=%d)", nt, bc, bc->type);
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

        BIC_HEADER tobich(eeh->m_type, bc->linker_type, BIC_TYPE_GUARDRAGON);
        BIC_GUARDRAGON tobicp;
        tobicp.biubiu = "Hello World, 机关傀儡";
        BIC_MESSAGE tobicm(&tobich, &tobicp);

        std::string tobicmsg;
        tobicm.Serialize(&tobicmsg);

        std::string tomsg;
        if (tobicmsg.empty()) {
            EEHERRO(eeh->logger, GIMM, "msg size is 0");
            return -1;
        }
        add_header(&tomsg, tobicmsg);

        eeh->m_linker_queues[bc->linker_type].push(tomsg);

        EEHINFO(eeh->logger, GIMM, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and heartbeat to eclient(%p, type=%d)", 
                tomsg.size(), bc->linker_type, eeh->m_linker_queues[bc->linker_type].size(), bc, bc->type);
        
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
    
    EEHINFO(eeh->logger, POLI, "do read from eclient(%p, type=%d)", bc, bc->type);
    
    char hbuf[NEGOHSIZE];
    ssize_t nh = read(fd, hbuf, NEGOHSIZE);
    if (nh != NEGOHSIZE) {
        EEHERRO(eeh->logger, POLI, "read(%ld != %lu): %s", nh, NEGOHSIZE, strerror(errno));
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
        EEHERRO(eeh->logger, POLI, "read(%ld != %lu): %s", nb, bodysize, strerror(errno));
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

    if (eeh->m_type != bich.orient) {
        EEHERRO(eeh->logger, POLI, "not belong here, discard the message");
        return 0;
    }
    
    EEHINFO(eeh->logger, POLI, "received msg(len=%lu, type=%d) from origin(linker=%d) to orient(linker=%d)",
                                                        bicmsg.size(), bich.type, bich.origin, bich.orient);

    if (bich.type == BIC_TYPE_GUARDRAGON) {
        BIC_GUARDRAGON bicguard;
        BIC_MESSAGE bicmguard(nullptr, &bicguard);
        
        bicmguard.ExtractPayload(bicmsg);
        EEHDBUG(eeh->logger, POLI, "BIC_GUARDRAGON.heartbeat: %ld", bicguard.heartbeat);
        EEHDBUG(eeh->logger, POLI, "BIC_GUARDRAGON.biubiu:    %s", bicguard.biubiu.c_str());
        eeh->m_heartbeats[bc->linker_type] = now_time();
    } else if (bich.type == BIC_TYPE_S2P_MONSTER) {
        BIC_MONSTER bicp;
        BIC_MESSAGE bicm(nullptr, &bicp);
        
        bicm.ExtractPayload(bicmsg);
        
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.name:        %s", bicp.name.c_str());
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.type:        %s", bicp.type.c_str());
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.attribute:   %s", bicp.attribute.c_str());
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.race:        %s", bicp.race.c_str());
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.level:       %u", bicp.level);
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.attack:      %u", bicp.attack);
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.defense:     %u", bicp.defense);
        EEHDBUG(eeh->logger, POLI, "BIC_MONSTER.description: %s", bicp.description.c_str());
    } else if (bich.type == BIC_TYPE_S2P_BOMBER) {
        BIC_BOMBER bicp;
        BIC_MESSAGE bicm(nullptr, &bicp);
        
        bicm.ExtractPayload(bicmsg);
        
        EEHDBUG(eeh->logger, POLI, "BIC_BOMBER.service_name: %s", bicp.service_name.c_str());
        EEHDBUG(eeh->logger, POLI, "BIC_BOMBER.service_type: %d", bicp.service_type);
        EEHDBUG(eeh->logger, POLI, "BIC_BOMBER.kill:         %s", bicp.kill ? "true" : "false");
        EEHDBUG(eeh->logger, POLI, "BIC_BOMBER.rescode:      %d", bicp.rescode);
        EEHDBUG(eeh->logger, POLI, "BIC_BOMBER.receipt:      %s", bicp.receipt.c_str());
    } else {
        EEHERRO(eeh->logger, POLI, "undefined or unhandled msg(%d)", (int)bich.type);
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
    
    EEHNS::SID_t linker_type;
    if (eeh->m_olinkers.find(fd) != eeh->m_olinkers.end()) {
        linker_type = eeh->m_olinkers[fd];
    } else {
        EEHERRO(eeh->logger, POLI, "an exceptions occurs");
        return -1;
    }
    
    EEHINFO(eeh->logger, POLI, "do write to eclient(%p, type=%d, linker_type=%d, queue_size=%lu)", 
                    bc, bc->type, linker_type, eeh->m_linker_queues[linker_type].size());
    
    while (eeh->m_linker_queues[linker_type].size() > 0) {
        std::string msg(eeh->m_linker_queues[linker_type].front());
        size_t nt = write(fd, msg.c_str(), msg.size());
        if (nt != msg.size()) {
            EEHERRO(eeh->logger, POLI, "write(%lu != %lu): %s", nt, msg.size(), strerror(errno));
            return -1;
        }
        eeh->m_linker_queues[linker_type].pop();

        EEHINFO(eeh->logger, POLI, "handled msg(len=%lu) to peer end of eclient(%p, type=%d)", nt, bc, bc->type);
    }
    
    return 0;
}

void serialize_policy_callback_BIC_SUMMON(EEHNS::SID_t linker_type, void *userp)
{
    std::string *bicmsg = dynamic_cast<std::string *>((std::string *)userp);
    
    BIC_HEADER bich(LINKER_TYPE_POLICY, linker_type, BIC_TYPE_P2S_SUMMON);
    BIC_SUMMON bicp;
    
    bicp.info = "召唤信息";
    if (linker_type == LINKER_TYPE_MADOLCHE) {
        DBUG("==========> MADOLCHE");
        bicp.sno = "ABYR-JP048";
        bicp.code = 37164373;
    } else if (linker_type == LINKER_TYPE_GIMMICKPUPPET) {
        DBUG("==========> GIMMICK PUPPET");
        bicp.sno = "PP16-JP010";
        bicp.code = 33776843;
    } else {
        return ;
    }

    BIC_MESSAGE bicm(&bich, &bicp);
    
    bicm.Serialize(bicmsg); 
}

void serialize_policy_callback_BIC_BITRON(EEHNS::SID_t linker_type, void *userp)
{
    std::string *bicmsg = dynamic_cast<std::string *>((std::string *)userp);
    
    BIC_HEADER bich(LINKER_TYPE_POLICY, linker_type, BIC_TYPE_P2S_BITRON);
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
    
    bicm.Serialize(bicmsg);
}

void serialize_policy_callback_BIC_BLOCKRON(EEHNS::SID_t linker_type, void *userp)
{
    ee_event_block_t *binfo = dynamic_cast<ee_event_block_t*>((ee_event_block_t*)userp);
    
    if (binfo->name.empty()) {
        binfo->use = 0;
        return;
    }
    
    binfo->use = 1;
    
    std::ifstream ifs(binfo->name.c_str(), std::ifstream::in | std::ifstream::binary);
    
    if (! ifs.is_open()) {
        return;
    }
    
    if (binfo->size == 0) {
        ifs.seekg(0, ifs.end);
        binfo->size = ifs.tellg();
        ifs.seekg(0, ifs.beg);
    }
    
    ifs.seekg(binfo->offset, ifs.beg);
    char buf[512];
    binfo->blocksize = (binfo->size - binfo->offset > 512) ? 512 : (binfo->size - binfo->offset);
    ifs.read(buf, binfo->blocksize);
    if (binfo->blocksize != ifs.gcount()) {
        ECHO(ERRO, "read(\"%s\"): %s", binfo->name.c_str(), strerror(errno));
        return;
    }
    
    BIC_HEADER bich(LINKER_TYPE_POLICY, linker_type, BIC_TYPE_P2S_BLOCKRON);
    BIC_BLOCKRON bicp;
    
    bicp.fname = binfo->name;
    bicp.fsize = binfo->size;
    bicp.offset = binfo->offset;
    bicp.blocksize = binfo->blocksize;
    bicp.block = std::string(buf, binfo->blocksize);
    
    BIC_MESSAGE bicm(&bich, &bicp);
    bicm.Serialize(binfo->bicmsg);
    
    binfo->offset += binfo->blocksize;
    if (binfo->offset == binfo->size) {
        binfo->use = 0;
    }
}

void serialize_policy_callback_BIC_BOMB(EEHNS::SID_t linker_type, void *userp)
{
    std::string *bicmsg = dynamic_cast<std::string *>((std::string *)userp);
    
    BIC_HEADER bich(LINKER_TYPE_POLICY, linker_type, BIC_TYPE_P2S_BOMBER);
    BIC_BOMBER bicp;
    
    bicp.service_name = "吃掉魔偶甜点 MADOLCHE 服务";
    bicp.service_type = linker_type;
    bicp.kill = true;
    
    BIC_MESSAGE bicm(&bich, &bicp);
    
    bicm.Serialize(bicmsg);
}

void serialize_bicmsg_policy(serialize_cb *cb, EEHNS::SID_t linker_type, void *userp)
{
    return cb(linker_type, userp);
}

int policy_timer_callback(void *args, void *userp)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)userp;
    EEHNS::BaseClient *bc = dynamic_cast<EEHNS::BaseClient*>((EEHNS::EClient*)args);
    if (! bc) {
        return -1;
    }
    
    static int use = 1;     // 0
    
    if (use) {
        eeh->m_info_block.use = 1;
        std::string name("test.tar.gz");
        eeh->m_info_block.name.resize(name.size());
        eeh->m_info_block.name.assign(name);
    }
    if (eeh->m_olinkers.find(bc->fd) != eeh->m_olinkers.end()) {
        if (now_time() - bc->heartbeat < 1 * 1000 && use == 0) {
            return 0;
        }
        bc->heartbeat = now_time();
        
        std::string tobicmsg;
                
        static BICTYPE type = BIC_TYPE_P2S_SUMMON; // BIC_TYPE_NONE;
        static EEHNS::SID_t linker_type = LINKER_TYPE_GIMMICKPUPPET; // LINKER_TYPE_MADOLCHE;
        if (use) {
            type = BIC_TYPE_P2S_BLOCKRON;
        }

        if (type == BIC_TYPE_P2S_BITRON) {          /** 比特传输 */
            linker_type = LINKER_TYPE_MADOLCHE;
            
            
            
            serialize_bicmsg_policy(serialize_policy_callback_BIC_BITRON, linker_type, &tobicmsg);
        } else if (type == BIC_TYPE_P2S_BLOCKRON) { /** 大文件传输 */
            linker_type = LINKER_TYPE_MADOLCHE;
            eeh->m_info_block.bicmsg = &tobicmsg;
            serialize_bicmsg_policy(serialize_policy_callback_BIC_BLOCKRON, linker_type, &eeh->m_info_block);
            if (eeh->m_info_block.use == 0) {
                use = 0;
                memset(&eeh->m_info_block, 0, sizeof(eeh->m_info_block));
            }
            type = BIC_TYPE_P2S_BOMBER;
        } else if (type == BIC_TYPE_P2S_BOMBER) {   /** 杀 Madolche */
            linker_type = LINKER_TYPE_MADOLCHE;
            serialize_bicmsg_policy(serialize_policy_callback_BIC_BOMB, linker_type, &tobicmsg);
            type = BIC_TYPE_P2S_SUMMON;
        } else if (type == BIC_TYPE_P2S_SUMMON) { /** 消息环回 */
            srand(time(nullptr));

            decltype(eeh->m_services_id.begin()) iterFind;
            if (rand() % 2) {
                iterFind = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "MADOLCHE"; });
                if (iterFind == m_services_id.end()) {
                    EEHERRO(eeh->logger, POLI, "could not find service id");
                    return -1;
                }
                BIC_HEADER bich(eeh->m_id, iterFind->sid, BIC_TYPE_P2S_SUMMON);
                BIC_SUMMON bicp;
                bicp.info = "召唤信息";
                bicp.sno = "ABYR-JP048";
                bicp.code = 37164373;
                
                BIC_MESSAGE bicm(&bich, &bicp);
                bicm.Serialize(&tobicmsg);
            } else {
                iterFind = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](const decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "GIMMICK_PUPPET"; });
                if (iterFind == m_services_id.end()) {
                    EEHERRO(eeh->logger, POLI, "could not find service id");
                    return -1;
                }
                BIC_HEADER bich(eeh->m_id, iterFind->sid, BIC_TYPE_P2S_SUMMON);
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
            EEHERRO(eeh->logger, POLI, "msg size is 0");
            return -1;
        }
        add_header(&tomsg, tobicmsg);
        
        eeh->m_linker_queues[bc->linker_type].push(tomsg);
        
        EEHINFO(eeh->logger, POLI, "pushed msg(len=%lu) to queue(linker=%d, size=%lu) and send to eclient(%p, type=%d)", 
                tomsg.size(), bc->linker_type, eeh->m_linker_queues[bc->linker_type].size(), bc, bc->type);
        
        eeh->EEH_mod(bc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
    }
    
    return 0;
}

ee_event_actions_t policy_callback_module = {
    policy_read_callback,
    policy_write_callback,
    policy_timer_callback,
};