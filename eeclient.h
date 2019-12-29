
#ifndef __Epoll_Ev_CLIENT_H__
#define __Epoll_Ev_CLIENT_H__

#include "include.h"
#include "eemodule.h"
#include "eehelper.h"

namespace EEHNS
{
	typedef enum {
		EEH_TYPE_TCP		= 1 << 0,
		EEH_TYPE_UDP		= 1 << 1,
		EEH_TYPE_PIPE       = 1 << 2,
		EEH_TYPE_FILE       = 1 << 3,
		
		EEH_TYPE_ALL        = -1,
	} EEHType;
	
	typedef enum {
		DO_NONE	       = 0 << 0,
		DO_ACCEPT      = 1 << 0,
		DO_READ        = 1 << 1,
		DO_WRITE       = 1 << 2,
		DO_CLOSE       = 1 << 3,
		
		DO_UNDEFINED   = -1,
	} ACTION_t;

	class EClient
	{
	public:
		virtual ~EClient() {}
	};

	class BaseClient : public EClient
	{
	public:
		ID_t                id;
		FD_t	            fd;
		EEHType             type;
		struct epoll_event  ev;
		std::string			host;
		PORT_t				port;
		ACTION_t			action;
		OPTION_t			prev_option;
		LINKER_TYPE			linker_type;		/** the service type between two ends */
		uint64_t			heartbeat;			/** record the time the heartbeat was sent */
		
		bool                is_server;			/** only for tcp server. whether is server or not */
		std::list<EClient*> clients;			/** only for tcp server. if as a server, this store its clients */
		ee_event_actions_t	clients_do;			/** only for tcp server. its clients would do */

		std::function<ssize_t(int, void*, size_t, void *)>			read_callback;
		std::function<ssize_t(int, const void *, size_t, void *)> 	write_callback;
		std::function<int(void*, void*)>							timer_callback;
	public:
		BaseClient(const BaseClient &) = delete;
		BaseClient &operator=(const BaseClient &) = delete;
		BaseClient(const BaseClient &&) = delete;
		BaseClient &operator=(const BaseClient &&) = delete;
		virtual ~BaseClient();
		explicit BaseClient(EEHType t);
		void set_actions(ee_event_actions_t actions);
	};
	
	class TcpClient : public BaseClient
	{
	public:
		TcpClient();
		TcpClient(FD_t fd, std::string host, PORT_t port, bool is_server = false);
		virtual ~TcpClient();
	};

	class UdpClient : public BaseClient
	{
	public:
		UdpClient();
		virtual ~UdpClient();
	};

	class PipeClient : public BaseClient
	{
	public:
		PipeClient() = delete;
		explicit PipeClient(FD_t fd);
		virtual ~PipeClient();
	};

	class FileClient : public BaseClient
	{
	public:
		FileClient();
		virtual ~FileClient();
	};
};

#endif // ! __Epoll_Ev_CLIENT_H__