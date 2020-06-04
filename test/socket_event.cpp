
#include "include.h"
#include "eehandler.h"
#include "eemodule.h"
#include "eefunc.h"

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_callback("TRANSFER",       daemon_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("MADOLCHE",       child_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("GIMMICK_PUPPET", child_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("SYNCHRON",       null_callback_module);
    
    EEHNS::EpollEvHandler::EEH_set_func("MADOLCHE",       test_function);
    EEHNS::EpollEvHandler::EEH_set_func("GIMMICK_PUPPET", test_function);
    
    rescode = eeh.EEH_init("event.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    eeh.EEH_run();

    eeh.EEH_destroy();
    
    return 0;
}