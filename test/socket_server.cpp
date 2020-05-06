
#include "include.h"
#include "eemodule.h"
#include "eehandler.h"
    
int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    EEHNS::EpollEvHandler eeh;
    // EEHNS::EEHErrCode rescode;
    
    eeh.EEH_init("eeh.ini");
    
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
    
    sleep(2);
    
    eeh.EEH_run();
    
    eeh.EEH_destroy();
    
    return 0;
}
