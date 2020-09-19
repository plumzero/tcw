
#include "include.h"
#include "eehandler.h"
#include "eemodule.h"
#include "eefunc.h"

const std::string INI_STRING = R"INI(

; GLOBAL options

; DBUF INFO WARN ERRO
LogLevel=DBUG
LogDir=/tmp
LogSize=5

[TRANSFER]
; `on` means whether start this process or not
on=no
; this would instruct current process to run as which behavior tagged by followed as-value:
;   `daemon` means run as a daemon process
;   `child`  means run as a child process created by a daemon
;   `server` means run as a independent tcp server 
;   `client` means run as a independent tcp client
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
        
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_func("POLICY",    server_function);
    
    rescode = eeh.EEH_init(ini.c_str());
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    eeh.EEH_run();
    
    eeh.EEH_destroy();
    
    return 0;
}
