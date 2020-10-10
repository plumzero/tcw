
#include "eehandler.h"
#include "eelog.h"
#include "msgid.h"
#include "msg.h"

const std::string INI_STRING = R"INI(

; GLOBAL options

; DBUF INFO WARN ERRO
LogLevel=DBUG
LogDir=./
LogSize=5

[TRANSFER]
on=no
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
        ECHO(INFO, "thread(tid=%lu) sleep for 10 seconds and wait for child process start", (uint64_t)pthread_self());
        sleep(10);
        int counter = 100;
        while (counter--) {
            uint64_t tosid = eeh.tcw_get_sid("POLICY");
            MSG_P2S_START st_start;
            st_start.is_start = true;
            st_start.information = "create a message and ready to send";

            std::string msg;
            st_start.Serialize(&msg);

            ECHO(INFO, "send a start message to(sid=%lu)", tosid);
            eeh.tcw_send_message(MSG_ID_P2S_START, tosid, msg);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
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
        case MSG_ID_P2S_START:
        {
            MSG_SUMMON st_summon;
            st_summon.info = "召唤信息";
            st_summon.sno = "ABAB-XYZ8";
            st_summon.code = 12345678;
            
            std::string tomsg;
            st_summon.Serialize(&tomsg);

            srand(time(nullptr));

            uint16_t tomsgid = MSG_ID_S2E_SUMMON;
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
        case MSG_ID_E2S_MONSTER:
        {
            MSG_MONSTER st_monster;
            st_monster.Structuralize(msg);
            
            Dbug(eeh->logger, TEST, "MSG_MONSTER.name:        %s", st_monster.name.c_str());
            Dbug(eeh->logger, TEST, "MSG_MONSTER.type:        %s", st_monster.type.c_str());
            Dbug(eeh->logger, TEST, "MSG_MONSTER.attribute:   %s", st_monster.attribute.c_str());
            Dbug(eeh->logger, TEST, "MSG_MONSTER.race:        %s", st_monster.race.c_str());
            Dbug(eeh->logger, TEST, "MSG_MONSTER.level:       %u", st_monster.level);
            Dbug(eeh->logger, TEST, "MSG_MONSTER.attack:      %u", st_monster.attack);
            Dbug(eeh->logger, TEST, "MSG_MONSTER.defense:     %u", st_monster.defense);
            Dbug(eeh->logger, TEST, "MSG_MONSTER.description: %s", st_monster.description.c_str());
            
            ECHO(INFO, "%s 收到来自 %s 服务的消息(type=%d)，一个测试流程结束。", eeh->m_services_id[eeh->m_id].c_str(), 
                        eeh->m_services_id[origin].c_str(), MSG_ID_E2S_MONSTER);
        }
        break;
        default:
            Erro(eeh->logger, TEST, "undefined or unhandled msg(%d)", (int)msgid);
    }
}