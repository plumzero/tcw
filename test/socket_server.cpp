
#include "eehandler.h"
#include "eelog.h"
#include "bic.h"
#include "msgid.h"

const std::string INI_STRING = R"INI(

; GLOBAL options

; DBUF INFO WARN ERRO
LogLevel=DBUG
LogDir=/tmp
LogSize=5

[TRANSFER]
; `on` means whether start this process or not
on=no
; this would instruct current process to run as which behavior tagged by followed as-value:
;   `daemon` means run as a daemon process
;   `child`  means run as a child process created by a daemon
;   `server` means run as a independent tcp server 
;   `client` means run as a independent tcp client
as=daemon

[DAEMON]
on=yes
as=daemon

[MADOLCHE]
on=no
as=child

[GIMMICK_PUPPET]
on=no
as=child

[POLICY]
; connect 服务只作为守护进程与外接连接的服务，所以其回调动作应该是守护进程的动作
; 所以不需要为 connect 服务独立设置动作
on=yes
as=server
listen=127.0.0.1:10036

)INI";

void server_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg);

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::string ini("server.ini");
    
    std::ofstream ofs(ini.c_str(), std::ofstream::out | std::ofstream::binary);
    if(! ofs.is_open()) {
        ECHO(ERRO, "open %s for writing failed", ini.c_str());
    }
    
    std::istringstream iss(INI_STRING);
    
    ofs << iss.rdbuf();
    ofs.close();
        
    tcw::EventHandler eeh;
    tcw::RetCode rescode;
    
    tcw::EventHandler::tcw_register_service("POLICY",    server_function);
    
    rescode = eeh.tcw_init(ini.c_str());
    if (rescode != tcw::OK) {
        ECHO(ERRO, "tcw_init failed");
        return -1;
    }
    
    std::thread th([&eeh](){
        ECHO(DBUG, "thread(tid=%lu) sleep for 6 seconds and wait for child process start", (uint64_t)pthread_self());
        sleep(6);

        uint64_t tosid = eeh.tcw_get_sid("POLICY");
        BIC_P2P_START bicstart;
        bicstart.is_start = true;
        bicstart.information = "create a message and ready to send";

        std::string msg;
        bicstart.Serialize(&msg);

        ECHO(DBUG, "send a start message to(sid=%lu)", tosid);
        eeh.tcw_send_message(BIC_TYPE_P2P_START, tosid, msg);
    });
    th.detach();

    eeh.tcw_run();
    
    eeh.tcw_destroy();
    
    return 0;
}

void server_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg)
{
    // (void) origin;
    (void) orient;
    tcw::EventHandler *eeh = (tcw::EventHandler *)arg;
    /** deal with the message, defined by programmer */
    switch (msgid) {
        case BIC_TYPE_P2P_START:
        {
            BIC_SUMMON bic_summon;
            bic_summon.info = "召唤信息";
            bic_summon.sno = "ABAB-XYZ8";
            bic_summon.code = 12345678;
            
            std::string tomsg;
            bic_summon.Serialize(&tomsg);

            srand(time(nullptr));

            uint16_t tomsgid = BIC_TYPE_P2S_SUMMON;
            uint64_t tosid = 0;

            decltype(eeh->m_services_id.begin()) iterTo;
            if (rand() % 2) {
                tosid = eeh->tcw_get_sid("MADOLCHE");
            } else {
                tosid = eeh->tcw_get_sid("GIMMICK_PUPPET");
            }
            eeh->tcw_send_message(tomsgid, tosid, tomsg);
            ECHO(INFO, "%s 发送给 %s 服务一条消息(type=%d)", eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str(), tomsgid);
        }
        break;
        case BIC_TYPE_S2P_MONSTER:
        {
            BIC_MONSTER bic;
            bic.Structuralize(msg);
            
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.name:        %s", bic.name.c_str());
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.type:        %s", bic.type.c_str());
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.attribute:   %s", bic.attribute.c_str());
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.race:        %s", bic.race.c_str());
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.level:       %u", bic.level);
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.attack:      %u", bic.attack);
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.defense:     %u", bic.defense);
            Dbug(eeh->logger, FUNC, "BIC_MONSTER.description: %s", bic.description.c_str());
            
            ECHO(INFO, "%s 收到来自 %s 服务的消息(type=%d)，一个测试流程结束。", eeh->m_services_id[eeh->m_id].c_str(), 
                        eeh->m_services_id[origin].c_str(), BIC_TYPE_S2P_MONSTER);
        }
        break;
        case BIC_TYPE_S2P_BOMBER:
        {
            BIC_BOMBER bic;
            bic.Structuralize(msg);
            
            Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
            Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bic.service_type);
            Dbug(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
            Dbug(eeh->logger, FUNC, "BIC_BOMBER.rescode:      %d", bic.rescode);
            Dbug(eeh->logger, FUNC, "BIC_BOMBER.receipt:      %s", bic.receipt.c_str());
        }
        break;
        default:
            Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
    }
}