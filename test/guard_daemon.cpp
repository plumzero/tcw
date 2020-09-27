
#include "eefunc.h"
#include "eehandler.h"
#include "eemodule.h"
#include "include.h"


const std::string INI_STRING = R"INI(

; GLOBAL options

; DBUG INFO WARN ERRO
LogLevel=DBUG
LogDir=./
LogSize=5

; `on` means whether start this process or not
; this would instruct current process to run as which behavior tagged by followed as-value:
;   `daemon` means run as a daemon process
;   `child`  means run as a child process created by a daemon
;   `server` means run as a independent tcp server 
;   `client` means run as a independent tcp client
[GUARD-DAEMON]
on=yes
as=daemon

[STEP-1]
on=yes
as=child

[STEP-2]
on=yes
as=child

[STEP-3]
on=yes
as=child

)INI";

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    
    std::string ini("guard.ini");
    
    std::ofstream ofs(ini.c_str(), std::ofstream::out | std::ofstream::binary);
    if(! ofs.is_open()) {
        ECHO(ERRO, "open %s for writing failed", ini.c_str());
    }
    
    std::istringstream iss(INI_STRING);
    
    ofs << iss.rdbuf();
    ofs.close();

    tcw::EventHandler eeh;
    tcw::RetCode rescode;

    tcw::EventHandler::tcw_register_service("STEP-1", step_1_function);
    tcw::EventHandler::tcw_register_service("STEP-2", step_2_function);
    tcw::EventHandler::tcw_register_service("STEP-3", step_3_function);

    rescode = eeh.tcw_init(ini.c_str());
    if (rescode != tcw::OK) {
        ECHO(ERRO, "tcw_init failed");
        return -1;
    }

    eeh.tcw_run();

    eeh.tcw_destroy();

    return 0;
}