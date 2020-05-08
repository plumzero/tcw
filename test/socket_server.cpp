
#include "include.h"
#include "eemodule.h"
#include "eehandler.h"
    
int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_services("DAEMON",         transfer_callback_module);
    EEHNS::EpollEvHandler::EEH_set_services("POLICY",         policy_callback_module);
    
    rescode = eeh.EEH_init("server.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    // EEHNS::EClient* ec_listen = 
        // eeh.EEH_TCP_listen("10.0.80.121", 8061, 
            // LINKER_TYPE_POLICY, EEHNS::EpollEvHandler::m_linkers_map[LINKER_TYPE_POLICY].second);
    // if (! ec_listen) {
        // printf("EEH_PIPE_create failed\n");
        // return -1;
    // }
    
    // rescode = eeh.EEH_add(ec_listen);
    // if (rescode != EEHNS::EEH_OK) {
        // printf("EEH_add failed\n");
        // return -1;
    // }

    eeh.EEH_run();
    
    eeh.EEH_destroy();
    
    return 0;
}
