
#include "eefunc.h"
#include "eehandler.h"
#include "eemodule.h"
#include "include.h"

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;

    EEHNS::EpollEvHandler::EEH_set_callback("GUARD-DAEMON", daemon_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("STEP-1", child_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("STEP-2", child_callback_module);
    EEHNS::EpollEvHandler::EEH_set_callback("STEP-3", child_callback_module);

    EEHNS::EpollEvHandler::EEH_set_func("STEP-1", step_1_function);
    EEHNS::EpollEvHandler::EEH_set_func("STEP-2", step_2_function);
    EEHNS::EpollEvHandler::EEH_set_func("STEP-3", step_3_function);

    rescode = eeh.EEH_init("guard.ini");
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }

    eeh.EEH_run();

    eeh.EEH_destroy();

    return 0;
}