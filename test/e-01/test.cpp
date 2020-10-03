
#include "eehandler.h"
#include "eelog.h"
#include "msgid.h"
#include "msg.h"

const std::string INI_STRING = R"INI(

LogLevel=DBUG
LogDir=./
LogSize=5

[DAEMON]
on=yes
as=daemon

[X]
on=yes
as=child

[Y]
on=yes
as=child

[Z]
on=yes
as=child

)INI";

/** IPC between sub process */
void X_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg);
void Y_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg);
void Z_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg);

const char * msg_x2x = "Hello World";
const char * msg_x2y = "this message come from X";
const char * msg_y2z = "this message come from Y";
const char * msg_z2x = "this message come from Z";

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    std::string ini("xyz.ini");
    
    std::ofstream ofs(ini.c_str(), std::ofstream::out | std::ofstream::binary);
    if(! ofs.is_open()) {
        ECHO(ERRO, "open %s for writing failed", ini.c_str());
    }
    
    std::istringstream iss(INI_STRING);
    
    ofs << iss.rdbuf();
    ofs.close();

    tcw::EventHandler eeh;
    tcw::RetCode rescode;

    tcw::EventHandler::tcw_register_service("X", X_function);
    tcw::EventHandler::tcw_register_service("Y", Y_function);
    tcw::EventHandler::tcw_register_service("Z", Z_function);

    rescode = eeh.tcw_init(ini.c_str());
    if (rescode != tcw::OK) {
        ECHO(ERRO, "tcw_init failed");
        return -1;
    }

    std::thread th([&eeh](){
        ECHO(DBUG, "thread(tid=%lu) sleep for 6 seconds and wait for child process start", (uint64_t)pthread_self());
        sleep(6);

        uint64_t tosid = eeh.tcw_get_sid("X");
        MSG_START bicstart;
        bicstart.timestamp = now_time();
        bicstart.information = msg_x2x;

        std::string msg;
        bicstart.Serialize(&msg);

        ECHO(DBUG, "send a start message to(sid=%lu)", tosid);
        eeh.tcw_send_message(MSG_ID_START, tosid, msg);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
    th.detach();

    eeh.tcw_run();

    eeh.tcw_destroy();

    return 0;
}

void  X_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg)
{
    (void) origin;
    (void) orient;

    tcw::EventHandler *eeh = (tcw::EventHandler *)arg;
    /** deal with the message, defined by programmer */
    switch (msgid) {
        case MSG_ID_START:
        {
            MSG_START st_start;
            st_start.Structuralize(msg);

            if (strcmp(st_start.information.c_str(), msg_x2x) != 0) {
                ECHO(ERRO, "error occured(X->X).");
                exit(-1);
            }

            // ECHO(DBUG, "MSG_START.timestamp: %lu",  st_start.timestamp);
            // ECHO(DBUG, "MSG_START.information: %s", st_start.information.c_str());

            MSG_X2Y st_x2y;
            st_x2y.count = 1;
            st_x2y.timestamp = st_start.timestamp;
            st_x2y.information = msg_x2y;
            
            uint16_t tomsgid = MSG_ID_X2Y;
            uint64_t tosid = eeh->tcw_get_sid("Y");
            std::string tomsg;
            st_x2y.Serialize(&tomsg);

            eeh->tcw_send_message(tomsgid, tosid, tomsg);
        }
        break;
        case MSG_ID_Z2X:
        {
            MSG_Z2X st_z2x;
            st_z2x.Structuralize(msg);

            if (strcmp(st_z2x.information.c_str(), msg_z2x) != 0) {
                ECHO(ERRO, "error occured(Z->X).");
                exit(-1);
            }

            // ECHO(DBUG, "MSG_Z2X.count: %d",       st_z2x.count);
            // ECHO(DBUG, "MSG_Z2X.timestamp: %lu",  st_z2x.timestamp);
            // ECHO(DBUG, "MSG_Z2X.information: %s", st_z2x.information.c_str());

            if (st_z2x.count < 10000) {
                MSG_X2Y st_x2y;
                st_x2y.count = st_z2x.count + 1;
                st_x2y.timestamp = st_z2x.timestamp;
                st_x2y.information = msg_x2y;
                
                uint16_t tomsgid = MSG_ID_X2Y;
                uint64_t tosid = eeh->tcw_get_sid("Y");
                std::string tomsg;
                st_x2y.Serialize(&tomsg);

                eeh->tcw_send_message(tomsgid, tosid, tomsg);
            } else {
                uint64_t cost = now_time() - st_z2x.timestamp;
                ECHO(DBUG, "test over. %d spend %lu milliseconds.", st_z2x.count, cost);
                if (cost > 1000) {
                    ECHO(DBUG, "tps=%f", (double)st_z2x.count / cost * 1000);
                }
            }
        }
        break;
        default:
            Erro(eeh->logger, TEST, "undefined or unhandled msg(%d)", (int)msgid);
    }
}

void Y_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg)
{
    (void) origin;
    (void) orient;
    tcw::EventHandler *eeh = (tcw::EventHandler *)arg;
    /** deal with the message, defined by programmer */
    switch (msgid) {
        case MSG_ID_X2Y:
        {
            MSG_X2Y st_x2y;
            st_x2y.Structuralize(msg);
            
            if (strcmp(st_x2y.information.c_str(), msg_x2y) != 0) {
                ECHO(ERRO, "error occured(X->Y).");
                exit(-1);
            }
            
            // ECHO(DBUG, "MSG_X2Y.count: %d",       st_x2y.count);
            // ECHO(DBUG, "MSG_X2Y.timestamp: %lu",  st_x2y.timestamp);
            // ECHO(DBUG, "MSG_X2Y.information: %s", st_x2y.information.c_str());
            
            MSG_Y2Z st_y2z;
            st_y2z.count = st_x2y.count + 1;
            st_y2z.timestamp = st_x2y.timestamp;
            st_y2z.information = msg_y2z;
            
            uint16_t tomsgid = MSG_ID_Y2Z;
            uint64_t tosid = eeh->tcw_get_sid("Z");
            std::string tomsg;
            st_y2z.Serialize(&tomsg);

            eeh->tcw_send_message(tomsgid, tosid, tomsg);
        }
        break;
        default:
            Erro(eeh->logger, TEST, "undefined or unhandled msg(%d)", (int)msgid);
    }
}
void Z_function(const uint16_t msgid, const uint64_t origin, const uint64_t orient, const std::string& msg, void* arg)
{
    (void) origin;
    (void) orient;
    tcw::EventHandler *eeh = (tcw::EventHandler *)arg;
    /** deal with the message, defined by programmer */
    switch (msgid) {
        case MSG_ID_Y2Z:
        {
            MSG_Y2Z st_y2z;
            st_y2z.Structuralize(msg);

            if (strcmp(st_y2z.information.c_str(), msg_y2z) != 0) {
                ECHO(ERRO, "error occured(Y->Z).");
                exit(-1);
            }
            
            // ECHO(DBUG, "MSG_Y2Z.count: %d",       st_y2z.count);
            // ECHO(DBUG, "MSG_Y2Z.timestamp: %lu",  st_y2z.timestamp);
            // ECHO(DBUG, "MSG_Y2Z.information: %s", st_y2z.information.c_str());

            MSG_Z2X st_z2x;
            st_z2x.count = st_y2z.count + 1;
            st_z2x.timestamp = st_y2z.timestamp;
            st_z2x.information = msg_z2x;

            uint16_t tomsgid = MSG_ID_Z2X;
            uint64_t tosid = eeh->tcw_get_sid("X");
            std::string tomsg;
            st_z2x.Serialize(&tomsg);

            eeh->tcw_send_message(tomsgid, tosid, tomsg);
        }
        break;
        default:
            Erro(eeh->logger, TEST, "undefined or unhandled msg(%d)", (int)msgid);
    }
}