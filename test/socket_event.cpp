
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
    
    rescode = eeh.EEH_init("event.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    eeh.EEH_run();

    eeh.EEH_destroy();
    
    return 0;
}