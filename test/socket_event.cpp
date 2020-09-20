
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
on=yes
; this would instruct current process to run as which behavior tagged by followed as-value:
;   `daemon` means run as a daemon process
;   `child`  means run as a child process created by a daemon
;   `server` means run as a independent tcp server 
;   `client` means run as a independent tcp client
as=daemon

[DAEMON]
on=no
as=daemon

[MADOLCHE]
on=yes
as=child

[GIMMICK_PUPPET]
on=yes
as=child

[SYNCHRON]
; listen 监听来自外部的连接，所以其回调动作应该是连接成功的客户端所要执行的动作
on=yes
as=server
listen=127.0.0.1:10012

[POLICY]
; connect 服务只作为守护进程与外接连接的服务，所以其回调动作应该是守护进程的动作
; 所以不需要为 connect 服务独立设置动作
on=yes
as=client
connect=127.0.0.1:10036

)INI";

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    
    std::string ini("event.ini");
    
    std::ofstream ofs(ini.c_str(), std::ofstream::out | std::ofstream::binary);
    if(! ofs.is_open()) {
        ECHO(ERRO, "open %s for writing failed", ini.c_str());
    }
    
    std::istringstream iss(INI_STRING);
    
    ofs << iss.rdbuf();
    ofs.close();
    
    EEHNS::EpollEvHandler eeh;
    EEHNS::EEHErrCode rescode;
    
    EEHNS::EpollEvHandler::EEH_set_func("MADOLCHE",       client_function);
    EEHNS::EpollEvHandler::EEH_set_func("GIMMICK_PUPPET", client_function);
    
    rescode = eeh.EEH_init(ini.c_str());
    if (rescode != EEHNS::EEH_OK) {
        ECHO(ERRO, "EEH_init failed");
        return -1;
    }
    
    eeh.EEH_run();

    eeh.EEH_destroy();
    
    return 0;
}