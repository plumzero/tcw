
#include "include.h"
#include "eemodule.h"
#include "eehandler.h"
    
int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_services("DAEMON",         daemon_callback_module);
    EEHNS::EpollEvHandler::EEH_set_services("POLICY",         policy_callback_module);
    
    rescode = eeh.EEH_init("server.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    eeh.EEH_run();
    
    eeh.EEH_destroy();
    
    return 0;
}
