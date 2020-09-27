
#include "eefunc.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

int check_message(const std::string& msg, uint64_t* fromsid, uint64_t* tosid, int32_t* mtype, void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;
    
    BIC_HEADER bich;
    BIC_MESSAGE bicm(&bich, nullptr);
    bicm.ExtractHeader(msg);
    
    if (eeh->m_id != bich.orient) {
        return -1;
    }
    
    *fromsid = bich.origin;
    *tosid = bich.origin;
    *mtype = bich.type;
    
    return 0;
}

int send_message(const int32_t mtype, const uint64_t tosid, BIC_BASE* tobicp, void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    if (mtype == BIC_TYPE_NONE || ! tobicp) {
        return -1;
    }
        
    std::string tomsg;
    BIC_HEADER tobich(eeh->m_id, tosid, (BICTYPE)mtype);
    BIC_MESSAGE tobicm(&tobich, tobicp);
    tobicm.Serialize(&tomsg);
    
    std::string tostream;
    add_header(&tostream, tomsg);
    if (tobicp != nullptr) {
        delete tobicp;
    }

    int tofd{0};
    if (eeh->m_pipe_pairs.find(eeh->m_id) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[eeh->m_id].second;
    } else {
        throw std::runtime_error("pipe pair not found");
    }

    tcw::BaseClient* tobc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        throw std::runtime_error("could not find the client");
    }

    eeh->m_linker_queues[tobc->sid].push(tostream);

    eeh->tcw_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

void* step_1_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;
    
    {
        BIC_HEADER tobich(eeh->m_id, eeh->m_id, BIC_TYPE_A2A_START);
        BIC_A2A_START bicstart;
        bicstart.is_start = true;
        bicstart.information = "create a message and ready to send";
        BIC_MESSAGE tobicm(&tobich, &bicstart);
        std::string tomsg;
        tobicm.Serialize(&tomsg);
        /** try lock */
        std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
        if (guard.try_lock()) {
            eeh->m_messages.push(std::move(tomsg));
        } else {
            // do nothing
        }
        ECHO(INFO, "%s 生成一条消息，准备发往 %s 服务",
                    eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[eeh->m_id].c_str());
        
    }
    
    while (true) {
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();

        uint64_t fromsid{0};
        uint64_t tosid{0};
        int32_t  mtype{0};
        if (check_message(msg, &fromsid, &tosid, &mtype, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        /** deal with the message, defined by programmer */
        switch (mtype) {
            case BIC_TYPE_A2A_START:
            {
                BIC_A2A_START bic;
                BIC_MESSAGE bicm(nullptr, &bic);
                
                bicm.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_A2A_START.is_start: %d", bic.is_start);
                Dbug(eeh->logger, FUNC, "BIC_A2A_START.information: %s", bic.information.c_str());
                
                BIC_A2B_BETWEEN* payload = new BIC_A2B_BETWEEN();
                payload->send = true;
                payload->information = "send command to NEXT service";
                
                tobicp = payload;
                totype = BIC_TYPE_A2B_BETWEEN;
                
                auto iterTo = std::find_if(
                    eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [&eeh](decltype(*eeh->m_services_id.begin())& ele) {
                        return ele.second == "STEP-2";
                    });
                if (iterTo == eeh->m_services_id.end()) {
                    /** it should not happen. */
                    Erro(eeh->logger, FUNC,
                            "could not find destination service");
                    tosid = 0;
                } else {
                    tosid = iterTo->first;
                    ECHO(INFO, "消息由 %s 服务向 %s 服务发送...", 
                        eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str());
                }
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)mtype);
        }
        /** try send message if needed */
        try {
            if (send_message(totype, tosid, tobicp, args) == 0) {
                Dbug(eeh->logger, FUNC, "pushed msg(type=%d) to que and forward to %s",
                                            totype, eeh->m_services_id[tosid].c_str());
            }
        }
        catch(std::exception& e) {
            Erro(eeh->logger, FUNC, "an exception occurs: %s", e.what());
        }
    }

    return nullptr;
}

void* step_2_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;
    
    while (true) {
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();

        uint64_t fromsid{0};
        uint64_t tosid{0};
        int32_t  mtype{0};
        if (check_message(msg, &fromsid, &tosid, &mtype, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        /** deal with the message, defined by programmer */
        switch (mtype) {
            case BIC_TYPE_A2B_BETWEEN:
            {
                BIC_A2B_BETWEEN bic;
                BIC_MESSAGE bicm(nullptr, &bic);
                
                bicm.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_A2B_BETWEEN.send: %d", bic.send);
                Dbug(eeh->logger, FUNC, "BIC_A2B_BETWEEN.information: %s", bic.information.c_str());
                
                BIC_B2C_BETWEEN* payload = new BIC_B2C_BETWEEN();
                payload->send = true;
                payload->information = "send command to NEXT service";
                
                tobicp = payload;
                totype = BIC_TYPE_B2C_BETWEEN;
                
                auto iterTo = std::find_if(
                    eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [&eeh](decltype(*eeh->m_services_id.begin())& ele) {
                        return ele.second == "STEP-3";
                    });
                if (iterTo == eeh->m_services_id.end()) {
                    /** it should not happen. */
                    Erro(eeh->logger, FUNC,
                            "could not find destination service");
                    tosid = 0;
                } else {
                    tosid = iterTo->first;
                    ECHO(INFO, "消息由 %s 服务向 %s 服务发送...", 
                        eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str());
                }
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)mtype);
        }
        /** try send message if needed */
        try {
            if (send_message(totype, tosid, tobicp, args) == 0) {
                Dbug(eeh->logger, FUNC, "pushed msg(type=%d) to que and forward to %s",
                                            totype, eeh->m_services_id[tosid].c_str());
            }
        }
        catch(std::exception& e) {
            Erro(eeh->logger, FUNC, "an exception occurs: %s", e.what());
        }
    }

    return nullptr;
}

void* step_3_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;
    
    while (true) {
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint64_t fromsid{0};
        uint64_t tosid{0};
        int32_t  mtype{0};
        if (check_message(msg, &fromsid, &tosid, &mtype, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        /** deal with the message, defined by programmer */
        switch (mtype) {
            case BIC_TYPE_B2C_BETWEEN:
            {
                BIC_B2C_BETWEEN bic;
                BIC_MESSAGE bicm(nullptr, &bic);
                
                bicm.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_B2C_BETWEEN.send: %d", bic.send);
                Dbug(eeh->logger, FUNC, "BIC_B2C_BETWEEN.information: %s", bic.information.c_str());
                
                // BIC_B2C_BETWEEN* payload = new BIC_B2C_BETWEEN();
                // payload->send = true;
                // payload->information = "send command to start STEP-3";
                
                // tobicp = payload;
                // totype = BIC_TYPE_B2C_BETWEEN;
                
                // auto iterTo = std::find_if(
                    // eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    // [&eeh](const decltype(*eeh->m_services_id.begin())& ele) {
                        // return ele.second == "STEP-3";
                    // });
                // if (iterTo == eeh->m_services_id.end()) {
                    // /** it should not happen. */
                    // Erro(eeh->logger, FUNC,
                            // "could not find destination service");
                    // tosid = 0;
                // } else {
                    // tosid = iterTo->first;
                // }
                // ECHO(INFO, "消息由 STEP-2 服务向 STEP-3 服务发送成功");
                ECHO(INFO, "%s 接收到来自 %s 的消息，一个流程结束。", eeh->m_services_id[eeh->m_id].c_str(),
                            eeh->m_services_id[fromsid].c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)mtype);
        }
        /** try send message if needed */
        try {
            if (send_message(totype, tosid, tobicp, args) == 0) {
                Dbug(eeh->logger, FUNC, "pushed msg(type=%d) to que and forward to %s",
                                            totype, eeh->m_services_id[tosid].c_str());
            }
        }
        catch(std::exception& e) {
            Erro(eeh->logger, FUNC, "an exception occurs: %s", e.what());
        }
    }

    return nullptr;
}

void* server_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    while (true) {
        {
            sleep(1);
            BIC_HEADER tobich(eeh->m_id, eeh->m_id, BIC_TYPE_P2P_START);
            BIC_P2P_START bicstart;
            bicstart.is_start = true;
            bicstart.information = "create a message and ready to send";
            BIC_MESSAGE tobicm(&tobich, &bicstart);
            std::string tomsg;
            tobicm.Serialize(&tomsg);
            /** try lock */
            std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
            if (guard.try_lock()) {
                eeh->m_messages.push(std::move(tomsg));
            } else {
                // do nothing
            }
            ECHO(INFO, "%s 生成一条起动消息", eeh->m_services_id[eeh->m_id].c_str());
        }
        
        srand(time(nullptr));
                
        decltype(eeh->m_services_id.begin()) iterTo;

        if (rand() % 2) {
            iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "MADOLCHE"; });
            if (iterTo == eeh->m_services_id.end()) {
                Erro(eeh->logger, FUNC, "could not find service id");
                return nullptr;
            }
        } else {
            iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "GIMMICK_PUPPET"; });
            if (iterTo == eeh->m_services_id.end()) {
                Erro(eeh->logger, FUNC, "could not find service id");
                return nullptr;
            }
        }
        
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint64_t fromsid{0};
        uint64_t tosid{0};
        int32_t  mtype{0};
        if (check_message(msg, &fromsid, &tosid, &mtype, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        /** deal with the message, defined by programmer */
        switch (mtype) {
            case BIC_TYPE_P2P_START:
            {                
                BIC_SUMMON* bicsumon = new BIC_SUMMON();
                bicsumon->info = "召唤信息";
                bicsumon->sno = "ABAB-XYZ8";
                bicsumon->code = 12345678;
                
                tosid = iterTo->first;
                tobicp = bicsumon;
                totype = BIC_TYPE_P2S_SUMMON;
                
                ECHO(INFO, "%s 发送给 %s 服务一条消息(type=%d)", eeh->m_services_id[eeh->m_id].c_str(), 
                            eeh->m_services_id[tosid].c_str(), totype);
            }
            break;
            case BIC_TYPE_S2P_MONSTER:
            {
                BIC_MONSTER bicp;
                BIC_MESSAGE bicm(nullptr, &bicp);
                
                bicm.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.name:        %s", bicp.name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.type:        %s", bicp.type.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.attribute:   %s", bicp.attribute.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.race:        %s", bicp.race.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.level:       %u", bicp.level);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.attack:      %u", bicp.attack);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.defense:     %u", bicp.defense);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.description: %s", bicp.description.c_str());
                
                ECHO(INFO, "%s 收到来自 %s 服务的消息(type=%d)，一个测试流程结束。", eeh->m_services_id[eeh->m_id].c_str(), 
                            eeh->m_services_id[tosid].c_str(), BIC_TYPE_S2P_MONSTER);
                
                // BIC_BOMBER* bicbomber = new BIC_BOMBER();
                // bicbomber->service_name = "销毁 " + eeh->m_services_id[iterTo->first]  + " 服务";
                // bicbomber->service_type = iterTo->first;
                // bicbomber->kill = true;
                
                // tobicp = bicbomber;
                // totype = BIC_TYPE_P2S_BOMBER;
            }
            break;
            case BIC_TYPE_S2P_BOMBER:
            {
                BIC_BOMBER bicp;
                BIC_MESSAGE bicm(nullptr, &bicp);
                
                bicm.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bicp.service_name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bicp.service_type);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bicp.kill ? "true" : "false");
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.rescode:      %d", bicp.rescode);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.receipt:      %s", bicp.receipt.c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)mtype);
        }
        /** try send message if needed */
        try {
            if (send_message(totype, tosid, tobicp, args) == 0) {
                Dbug(eeh->logger, FUNC, "pushed msg(type=%d) to que and forward to %s",
                                            totype, eeh->m_services_id[tosid].c_str());
            }
        }
        catch(std::exception& e) {
            Erro(eeh->logger, FUNC, "an exception occurs: %s", e.what());
        }
    }

    return nullptr;
}

void* client_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    while (true) {
        {
            // sleep(1);
            // BIC_HEADER tobich(eeh->m_id, eeh->m_id, BIC_TYPE_P2P_START);
            // BIC_P2P_START bicstart;
            // bicstart.is_start = true;
            // bicstart.information = "create a message and ready to send";
            // BIC_MESSAGE tobicm(&tobich, &bicstart);
            // std::string tomsg;
            // tobicm.Serialize(&tomsg);
            // /** try lock */
            // std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
            // if (guard.try_lock()) {
                // eeh->m_messages.push(std::move(tomsg));
            // } else {
                // // do nothing
            // }
            // ECHO(INFO, "%s 生成一条消息，准备发往 %s 服务",
                        // eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[eeh->m_id].c_str());
        }
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint64_t fromsid{0};
        uint64_t tosid{0};
        int32_t  mtype{0};
        if (check_message(msg, &fromsid, &tosid, &mtype, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        /** deal with the message, defined by programmer */
        switch (mtype) {
            case BIC_TYPE_P2P_START:
            {                
                BIC_MONSTER* monster = new BIC_MONSTER();
                monster->name = eeh->m_services_id[eeh->m_id];
                monster->type = "service";
                monster->attribute = "process";
                monster->race = "Fairy";
                monster->level = 4;
                monster->attack = 2200;
                monster->defense = 2100;
                monster->description = "当前的服务名称是 " + eeh->m_services_id[eeh->m_id];

                auto iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "POLICY"; });
                if (iterTo == eeh->m_services_id.end()) {
                    Erro(eeh->logger, FUNC, "could not find service id");
                    return nullptr;
                }
                
                totype = BIC_TYPE_S2P_MONSTER;
                tosid = iterTo->first;
                tobicp = monster;                
            }
            break;
            case BIC_TYPE_P2S_SUMMON:
            {
                BIC_SUMMON bic;
                BIC_MESSAGE bicsummon(nullptr, &bic);
                
                bicsummon.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.info:  %s", bic.info.c_str());
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.code:  %lu", bic.code);
                
                BIC_MONSTER* monster = new BIC_MONSTER();
                monster->name = eeh->m_services_id[eeh->m_id];
                monster->type = "service";
                monster->attribute = "process";
                monster->race = "Fairy";
                monster->level = 4;
                monster->attack = 2200;
                monster->defense = 2100;
                monster->description = "当前的服务名称是 " + eeh->m_services_id[eeh->m_id];
                
                tobicp = monster;
                totype = BIC_TYPE_S2P_MONSTER;
                
                ECHO(INFO, "%s 收到消息(type=%d)，并发回给 %s 服务一条消息(type=%d)",
                            eeh->m_services_id[eeh->m_id].c_str(), BIC_TYPE_P2S_SUMMON,
                            eeh->m_services_id[tosid].c_str(), totype);
            }
            break;
            case BIC_TYPE_P2S_BOMBER:
            {
                BIC_BOMBER bic;
                BIC_MESSAGE bicbomb(nullptr, &bic);
                
                bicbomb.ExtractPayload(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bic.service_type);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
                
                BIC_BOMBER* bomb = new BIC_BOMBER();
                bomb->service_name = bic.service_name;
                bomb->service_type = bic.service_type;
                bomb->kill = bic.kill;
                bomb->rescode = 1;
                bomb->receipt = eeh->m_services_id[eeh->m_id] + " 服务将在 1 秒内被销毁";
                
                signal(SIGALRM, tcw::signal_release);
                alarm(2);
                Dbug(eeh->logger, FUNC, "pid %d would be destructed in 2 seconds", getpid());
                
                tobicp = bomb;
                totype = BIC_TYPE_S2P_BOMBER;
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)mtype);
        }
        /** try send message if needed */
        try {
            if (send_message(totype, tosid, tobicp, args) == 0) {
                Dbug(eeh->logger, FUNC, "pushed msg(type=%d) to que and forward to %s",
                                            totype, eeh->m_services_id[tosid].c_str());
            }
        }
        catch(std::exception& e) {
            Erro(eeh->logger, FUNC, "an exception occurs: %s", e.what());
        }
    }

    return nullptr;
}