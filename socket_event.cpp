
#include "include.h"
#include "eehandler.h"
#include "eemodule.h"

int main(int argc, char *argv[])
{
	EEHNS::EpollEvHandler::m_info_process[getpid()] = 
			EEHNS::EpollEvHandler::m_linkers_map[SERVER_TYPE_TRANSFER].first;
	
	ECHO(INFO, "service %s(pid=%d): start ...", 
				EEHNS::EpollEvHandler::m_info_process[getpid()].c_str(), getpid());
	
	EEHNS::EpollEvHandler eeh;
	EEHNS::EEHErrCode rescode;
	eeh.EEH_init(SERVER_TYPE_TRANSFER);
	
	EEHNS::EClient* ec_listen = eeh.EEH_TCP_listen("192.168.43.228", 8070, 
													SERVER_TYPE_SYNCHRON, null_callback_module);
	if (! ec_listen) {
		ECHO(ERRO, "EEH_TCP_listen failed");
		return -1;
	}
	rescode = eeh.EEH_add(ec_listen);
	if (rescode != EEHNS::EEH_OK) {
		ECHO(ERRO, "EEH_add failed");
		return -1;
	}
	
	EEHNS::EClient* ec_client = eeh.EEH_TCP_connect("192.168.43.228", 8061, LINKER_TYPE_POLICY);
	if (! ec_client) {
		ECHO(ERRO, "EEH_TCP_connect failed");
		return -1;
	}
	
	rescode = eeh.EEH_add(ec_client);
	if (rescode != EEHNS::EEH_OK) {
		ECHO(ERRO, "EEH_add failed");
		return -1;
	}
	dynamic_cast<EEHNS::BaseClient*>(ec_client)->set_actions(transfer_callback_module);
	
	eeh.EEH_run();

	eeh.EEH_destroy();
	
	return 0;
}