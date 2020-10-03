
#include "eehandler.h"
#include "eelog.h"
#include "msgid.h"
#include "msg.h"

const std::string INI_STRING = R"INI(

; GLOBAL options

; DBUF INFO WARN ERRO
LogLevel=DBUG
LogDir=/tmp
LogSize=5

[TRANSFER]
; `on` means whether start this process or not
on=yes
; this would instruct current process to run as which behavior tagged by followed as-value:
;   `daemon` means run as a daemon process
;   `child`  means run as a child process created by a daemon
;   `server` means run as a independent tcp server 
;   `client` means run as a independent tcp client
as=daemon

[DAEMON]
on=no
as=daemon

[MADOLCHE]
on=yes
as=child

[GIMMICK_PUPPET]
on=yes
as=child

[SYNCHRON]
; listen 监听来自外部的连接，所以其回调动作应该是连接成功的客户端所要执行的动作
on=yes
as=server
listen=127.0.0.1:10012

[POLICY-CLIENT]
; connect 服务只作为守护进程与外接连接的服务，所以其回调动作应该是守护进程的动作
; 所以不需要为 connect 服务独立设置动作
on=yes
as=client
connect=127.0.0.1:10036
service=POLICY

)INI";

void client_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg);

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::string ini("event.ini");
    
    std::ofstream ofs(ini.c_str(), std::ofstream::out | std::ofstream::binary);
    if(! ofs.is_open()) {
        ECHO(ERRO, "open %s for writing failed", ini.c_str());
    }
    
    std::istringstream iss(INI_STRING);
    
    ofs << iss.rdbuf();
    ofs.close();
    
    tcw::EventHandler eeh;
    tcw::RetCode rescode;
    
    tcw::EventHandler::tcw_register_service("MADOLCHE",       client_function);
    tcw::EventHandler::tcw_register_service("GIMMICK_PUPPET", client_function);
    
    rescode = eeh.tcw_init(ini.c_str());
    if (rescode != tcw::OK) {
        ECHO(ERRO, "tcw_init failed");
        return -1;
    }
    
    eeh.tcw_run();

    eeh.tcw_destroy();
    
    return 0;
}


void client_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg)
{
    // (void) origin;
    (void) orient;
    tcw::EventHandler *eeh = (tcw::EventHandler *)arg;
    /** deal with the message, defined by programmer */
    switch (msgid) {
        case MSG_ID_P2S_SUMMON:
        {
            MSG_SUMMON bic;
            bic.Structuralize(msg);
            
            Dbug(eeh->logger, TEST, "BIC_SUMMON.info:  %s",  bic.info.c_str());
            Dbug(eeh->logger, TEST, "BIC_SUMMON.sno:   %s",  bic.sno.c_str());
            Dbug(eeh->logger, TEST, "BIC_SUMMON.code:  %lu", bic.code);
            
            MSG_MONSTER bic_monster;
            bic_monster.name = eeh->m_services_id[eeh->m_id];
            bic_monster.type = "service";
            bic_monster.attribute = "process";
            bic_monster.race = "Fairy";
            bic_monster.level = 4;
            bic_monster.attack = 2200;
            bic_monster.defense = 2100;
            bic_monster.description = "当前的服务名称是 " + eeh->m_services_id[eeh->m_id];
            
            std::string tomsg;
            bic_monster.Serialize(&tomsg);

            uint16_t tomsgid = MSG_ID_S2P_MONSTER;
            uint64_t tosid = origin;
            
            eeh->tcw_send_message(tomsgid, tosid, tomsg);
            ECHO(INFO, "%s 收到消息(type=%d)，并发回给 %s 服务一条消息(type=%d)",
                        eeh->m_services_id[eeh->m_id].c_str(), MSG_ID_P2S_SUMMON,
                        eeh->m_services_id[tosid].c_str(), tomsgid);
        }
        break;
        default:
            Erro(eeh->logger, TEST, "undefined or unhandled msg(%d)", (int)msgid);
    }
}
