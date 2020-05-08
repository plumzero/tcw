
#include "include.h"
#include "eehandler.h"
#include "eemodule.h"

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_services("TRANSFER",       transfer_callback_module);
    EEHNS::EpollEvHandler::EEH_set_services("MADOLCHE",       madolche_callback_module);
    EEHNS::EpollEvHandler::EEH_set_services("GIMMICK_PUPPET", gimmickpuppet_callback_module);
    EEHNS::EpollEvHandler::EEH_set_services("SYNCHRON",       null_callback_module);
    rescode = eeh.EEH_init("eeh.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    ECHO(INFO, "service %s(pid=%d): start ...", eeh.m_info_process[getpid()].c_str(), getpid());
    
    // // eeh.m_info_process[getpid()] = 
            // // m_linkers_map[SERVER_TYPE_TRANSFER].first;
    
    // // EEHNS::EClient* ec_listen = eeh.EEH_TCP_listen("10.0.80.121", 8070, 
                                                    // // SERVER_TYPE_SYNCHRON, null_callback_module);
    // // if (! ec_listen) {
        // // ECHO(ERRO, "EEH_TCP_listen failed");
        // // return -1;
    // // }
    // // rescode = eeh.EEH_add(ec_listen);
    // // if (rescode != EEHNS::EEH_OK) {
        // // ECHO(ERRO, "EEH_add failed");
        // // return -1;
    // // }
    
    // // EEHNS::EClient* ec_client = eeh.EEH_TCP_connect("10.0.80.121", 8061, LINKER_TYPE_POLICY);
    // // if (! ec_client) {
        // // ECHO(ERRO, "EEH_TCP_connect failed");
        // // return -1;
    // // }
    
    // // rescode = eeh.EEH_add(ec_client);
    // // if (rescode != EEHNS::EEH_OK) {
        // // ECHO(ERRO, "EEH_add failed");
        // // return -1;
    // // }
    // // dynamic_cast<EEHNS::BaseClient*>(ec_client)->set_actions(transfer_callback_module);
    
    eeh.EEH_run();

    eeh.EEH_destroy();
    
    return 0;
}