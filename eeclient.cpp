
#include "eeclient.h"

namespace tcw
{
    static int s_eeh_id = 0;    /** maybe chaos */
    
    /** BaseClient */
    BaseClient::BaseClient(ClientType t) 
        : fd(-1), action(DO_NONE), prev_option(0)
    {
        type = t;
        id = ++s_eeh_id;
        clients.clear();
        heartbeat = now_time();
        memset(&ev, 0, sizeof(ev));
        host.clear();
        port = 0;
        sid = 0;
        is_server = false;
        clients_do = child_callback_module;
        
        set_actions(child_callback_module);
    }
    BaseClient::~BaseClient()
    {
    }
    void BaseClient::set_actions(event_actions_t actions)
    {
        using namespace std::placeholders;
        this->read_callback  = std::bind(actions.do_read, _1, _2, _3, _4);
        this->write_callback = std::bind(actions.do_write, _1, _2, _3, _4);
        this->timer_callback = std::bind(actions.do_timer, _1, _2);
    }
    /** TcpClient */
    TcpClient::TcpClient() 
        : BaseClient(TYPE_TCP)
    {
    }
    TcpClient::TcpClient(FD_t fd, std::string host, PORT_t port, bool is_server)
        : BaseClient(TYPE_TCP) 
    {
        this->fd = fd;
        this->host = host;
        this->port = port;
        this->is_server = is_server;
    }
    TcpClient::~TcpClient()
    {
        if (fd > 0) close(fd);
    }
    /** UdpClient */
    UdpClient::UdpClient() 
        : BaseClient(TYPE_UDP)
    {
    }
    UdpClient::~UdpClient()
    {
        if (fd > 0) close(fd);
    }
    /** PipeClient */
    PipeClient::PipeClient(FD_t fd)
        : BaseClient(TYPE_PIPE)
    {
        this->fd = fd;  
    }
    PipeClient::~PipeClient()
    {
        if (fd > 0) close(fd);
    }
    /** FileClient */
    FileClient::FileClient() 
        : BaseClient(TYPE_FILE)
    {
    }
    FileClient::~FileClient()
    {
        if (fd > 0) close(fd);
    }

};