
#include "eefunc.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

int check_message(const std::string& stream, uint16_t* msgid, uint64_t* origin, uint64_t* orient, std::string* msg, void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    if (stream.size() <= sizeof(NegoHeader)) {
        return -1;
    }

    NegoHeader header;
    memcpy(&header, stream.c_str(), sizeof(NegoHeader));

    if (eeh->m_id != header.orient) {
        return -1;
    }

    *msgid = ntohs(header.msgid);
    *origin = header.origin;
    *orient = header.orient;

    size_t bodysize = ntohs(header.bodysize);

    msg->assign(stream.c_str() + sizeof(NegoHeader), bodysize);

    return 0;
}

int send_message(const uint16_t msgid, const uint64_t tosid, const std::string& msg, void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    std::string tostream;

    add_header(&tostream, msgid, eeh->m_id, tosid, msg);

    int tofd = 0;
    if (eeh->m_pipe_pairs.find(eeh->m_id) != eeh->m_pipe_pairs.end()) {
        tofd = eeh->m_pipe_pairs[eeh->m_id].second;
    } else {
        Erro(eeh->logger, FUNC, "pipe pair not found");
        return -1;
    }

    tcw::BaseClient* tobc = dynamic_cast<tcw::BaseClient*>(eeh->m_clients[tofd]);
    if (! tobc) {
        Erro(eeh->logger, FUNC, "could not find the client");
        return -1;
    }

    eeh->m_linker_queues[tobc->sid].push(tostream);

    eeh->tcw_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);

    return 0;
}

int step_1_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    {
        sleep(1);
        BIC_A2A_START bicstart;
        bicstart.is_start = true;
        bicstart.information = "create a message and ready to send";

        std::string tomsg, tostream;
        bicstart.Serialize(&tomsg);

        add_header(&tostream, BIC_TYPE_A2A_START, eeh->m_id, eeh->m_id, tomsg);
        /** try lock */
        std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
        if (guard.try_lock()) {
            eeh->m_messages.push(std::move(tostream));
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
        
        std::string stream = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();

        uint16_t msgid = 0;
        uint64_t origin = 0;
        uint64_t orient = 0;
        std::string msg;
        if (check_message(stream, &msgid, &origin, &orient, &msg, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        /** deal with the message, defined by programmer */
        switch (msgid) {
            case BIC_TYPE_A2A_START:
            {
                BIC_A2A_START bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_A2A_START.is_start: %d", bic.is_start);
                Dbug(eeh->logger, FUNC, "BIC_A2A_START.information: %s", bic.information.c_str());

                BIC_A2B_BETWEEN bic_a2b;
                bic_a2b.send = true;
                bic_a2b.information = "send command to NEXT service";
                
                std::string tomsg;
                bic_a2b.Serialize(&tomsg);

                uint16_t tomsgid = BIC_TYPE_A2B_BETWEEN;
                uint64_t tosid = 0;
                
                auto iterTo = std::find_if(
                    eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [&eeh](decltype(*eeh->m_services_id.begin())& ele) {
                        return ele.second == "STEP-2";
                    });
                if (iterTo == eeh->m_services_id.end()) {
                    /** it should not happen. */
                    Erro(eeh->logger, FUNC, "could not find destination service");
                    return -1;
                } else {
                    tosid = iterTo->first;
                }
                send_message(tomsgid, tosid, tomsg, args);
                ECHO(INFO, "消息由 %s 服务向 %s 服务发送...", eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
        }
    }

    return 0;
}

int step_2_function(void* args)
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
        
        std::string stream = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();

        uint16_t msgid = 0;
        uint64_t origin = 0;
        uint64_t orient = 0;
        std::string msg;
        if (check_message(stream, &msgid, &origin, &orient, &msg, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        /** deal with the message, defined by programmer */
        switch (msgid) {
            case BIC_TYPE_A2B_BETWEEN:
            {
                BIC_A2B_BETWEEN bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_A2B_BETWEEN.send: %d", bic.send);
                Dbug(eeh->logger, FUNC, "BIC_A2B_BETWEEN.information: %s", bic.information.c_str());
                
                BIC_B2C_BETWEEN bic_b2c;
                bic_b2c.send = true;
                bic_b2c.information = "send command to NEXT service";
                
                std::string tomsg;
                bic_b2c.Serialize(&tomsg);

                uint16_t tomsgid = BIC_TYPE_B2C_BETWEEN;
                uint64_t tosid = 0;
                
                auto iterTo = std::find_if(
                    eeh->m_services_id.begin(), eeh->m_services_id.end(),
                    [&eeh](decltype(*eeh->m_services_id.begin())& ele) {
                        return ele.second == "STEP-3";
                    });
                if (iterTo == eeh->m_services_id.end()) {
                    /** it should not happen. */
                    Erro(eeh->logger, FUNC, "could not find destination service");
                    return -1;
                } else {
                    tosid = iterTo->first;
                }
                send_message(tomsgid, tosid, tomsg, args);
                ECHO(INFO, "消息由 %s 服务向 %s 服务发送...", eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
        }
    }

    return 0;
}

int step_3_function(void* args)
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
        
        std::string stream = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint16_t msgid = 0;
        uint64_t origin = 0;
        uint64_t orient = 0;
        std::string msg;
        if (check_message(stream, &msgid, &origin, &orient, &msg, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        /** deal with the message, defined by programmer */
        switch (msgid) {
            case BIC_TYPE_B2C_BETWEEN:
            {
                BIC_B2C_BETWEEN bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_B2C_BETWEEN.send: %d", bic.send);
                Dbug(eeh->logger, FUNC, "BIC_B2C_BETWEEN.information: %s", bic.information.c_str());
                
                ECHO(INFO, "%s 接收到来自 %s 的消息，一个流程结束。", eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[origin].c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
        }
    }

    return 0;
}

int server_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    while (true) {
        {
            sleep(1);
            BIC_P2P_START bicstart;
            bicstart.is_start = true;
            bicstart.information = "create a message and ready to send";

            std::string tomsg, tostream;
            bicstart.Serialize(&tomsg);

            add_header(&tostream, BIC_TYPE_P2P_START, eeh->m_id, eeh->m_id, tomsg);
            /** try lock */
            std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
            if (guard.try_lock()) {
                eeh->m_messages.push(std::move(tostream));
            } else {
                // do nothing
            }
            ECHO(INFO, "%s 生成一条起动消息", eeh->m_services_id[eeh->m_id].c_str());
        }
                
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string stream = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint16_t msgid = 0;
        uint64_t origin = 0;
        uint64_t orient = 0;
        std::string msg;
        if (check_message(stream, &msgid, &origin, &orient, &msg, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        /** deal with the message, defined by programmer */
        switch (msgid) {
            case BIC_TYPE_P2P_START:
            {
                BIC_SUMMON bic_summon;
                bic_summon.info = "召唤信息";
                bic_summon.sno = "ABAB-XYZ8";
                bic_summon.code = 12345678;
                
                std::string tomsg;
                bic_summon.Serialize(&tomsg);

                srand(time(nullptr));

                uint16_t tomsgid = BIC_TYPE_P2S_SUMMON;
                uint64_t tosid = 0;

                decltype(eeh->m_services_id.begin()) iterTo;
                if (rand() % 2) {
                    iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                            [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "MADOLCHE"; });
                    if (iterTo == eeh->m_services_id.end()) {
                        Erro(eeh->logger, FUNC, "could not find service id");
                        return -1;
                    } else {
                        tosid = iterTo->first;
                    }
                } else {
                    iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                            [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "GIMMICK_PUPPET"; });
                    if (iterTo == eeh->m_services_id.end()) {
                        Erro(eeh->logger, FUNC, "could not find service id");
                        return -1;
                    } else {
                        tosid = iterTo->first;
                    }
                }
                send_message(tomsgid, tosid, tomsg, args);
                ECHO(INFO, "%s 发送给 %s 服务一条消息(type=%d)", eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[tosid].c_str(), tomsgid);
            }
            break;
            case BIC_TYPE_S2P_MONSTER:
            {
                BIC_MONSTER bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.name:        %s", bic.name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.type:        %s", bic.type.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.attribute:   %s", bic.attribute.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.race:        %s", bic.race.c_str());
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.level:       %u", bic.level);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.attack:      %u", bic.attack);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.defense:     %u", bic.defense);
                Dbug(eeh->logger, FUNC, "BIC_MONSTER.description: %s", bic.description.c_str());
                
                ECHO(INFO, "%s 收到来自 %s 服务的消息(type=%d)，一个测试流程结束。", eeh->m_services_id[eeh->m_id].c_str(), 
                            eeh->m_services_id[origin].c_str(), BIC_TYPE_S2P_MONSTER);
            }
            break;
            case BIC_TYPE_S2P_BOMBER:
            {
                BIC_BOMBER bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bic.service_type);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.rescode:      %d", bic.rescode);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.receipt:      %s", bic.receipt.c_str());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
        }
    }

    return 0;
}

int client_function(void* args)
{
    tcw::EventHandler *eeh = (tcw::EventHandler *)args;

    while (true) {
        {
            // sleep(1);
            // BIC_P2P_START bicstart;
            // bicstart.is_start = true;
            // bicstart.information = "create a message and ready to send";

            // std::string tomsg, tostream;
            // bicstart.Serialize(&tomsg);

            // add_header(&tostream, BIC_TYPE_P2P_START, eeh->m_id, eeh->m_id, tomsg);
            // /** try lock */
            // std::unique_lock<std::mutex> guard(eeh->m_mutex, std::defer_lock);
            // if (guard.try_lock()) {
            //     eeh->m_messages.push(std::move(tomsg));
            // } else {
            //     // do nothing
            // }
            // ECHO(INFO, "%s 生成一条起动消息", eeh->m_services_id[eeh->m_id].c_str());
        }
        /** wait for the message to deal with */
        std::unique_lock<std::mutex> guard(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(guard, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            Dbug(eeh->logger, FUNC, "thread msg queue is empty");
            continue;
        }
        Dbug(eeh->logger, FUNC, "deal with thread msg queue(size=%lu)", eeh->m_messages.size());
        
        std::string stream = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        guard.unlock();
        
        uint16_t msgid = 0;
        uint64_t origin = 0;
        uint64_t orient = 0;
        std::string msg;
        if (check_message(stream, &msgid, &origin, &orient, &msg, args) != 0) {
            Erro(eeh->logger, FUNC, "not belong here, discard this message");
            continue;
        }
        
        /** deal with the message, defined by programmer */
        switch (msgid) {
            case BIC_TYPE_P2P_START:
            {
                BIC_MONSTER bic_monster;
                bic_monster.name = eeh->m_services_id[eeh->m_id];
                bic_monster.type = "service";
                bic_monster.attribute = "process";
                bic_monster.race = "Fairy";
                bic_monster.level = 4;
                bic_monster.attack = 2200;
                bic_monster.defense = 2100;
                bic_monster.description = "当前的服务名称是 " + eeh->m_services_id[eeh->m_id];

                std::string tomsg;
                bic_monster.Serialize(&tomsg);

                uint16_t tomsgid = BIC_TYPE_S2P_MONSTER;
                uint64_t tosid = 0;

                auto iterTo = std::find_if(eeh->m_services_id.begin(), eeh->m_services_id.end(),
                        [](decltype(*eeh->m_services_id.begin())& ele){ return ele.second == "POLICY"; });
                if (iterTo == eeh->m_services_id.end()) {
                    Erro(eeh->logger, FUNC, "could not find service id");
                    return -1;
                } else {
                    tosid = iterTo->first;
                }
                send_message(tomsgid, tosid, tomsg, args);              
            }
            break;
            case BIC_TYPE_P2S_SUMMON:
            {
                BIC_SUMMON bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.info:  %s",  bic.info.c_str());
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.sno:   %s",  bic.sno.c_str());
                Dbug(eeh->logger, FUNC, "BIC_SUMMON.code:  %lu", bic.code);
                
                BIC_MONSTER bic_monster;
                bic_monster.name = eeh->m_services_id[eeh->m_id];
                bic_monster.type = "service";
                bic_monster.attribute = "process";
                bic_monster.race = "Fairy";
                bic_monster.level = 4;
                bic_monster.attack = 2200;
                bic_monster.defense = 2100;
                bic_monster.description = "当前的服务名称是 " + eeh->m_services_id[eeh->m_id];
                
                std::string tomsg;
                bic_monster.Serialize(&tomsg);

                uint16_t tomsgid = BIC_TYPE_S2P_MONSTER;
                uint64_t tosid = origin;
                
                send_message(tomsgid, tosid, tomsg, args);
                ECHO(INFO, "%s 收到消息(type=%d)，并发回给 %s 服务一条消息(type=%d)",
                            eeh->m_services_id[eeh->m_id].c_str(), BIC_TYPE_P2S_SUMMON,
                            eeh->m_services_id[tosid].c_str(), tomsgid);
            }
            break;
            case BIC_TYPE_P2S_BOMBER:
            {
                BIC_BOMBER bic;
                bic.Structuralize(msg);
                
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bic.service_type);
                Dbug(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
                
                BIC_BOMBER bic_bomb;
                bic_bomb.service_name = bic.service_name;
                bic_bomb.service_type = bic.service_type;
                bic_bomb.kill = bic.kill;
                bic_bomb.rescode = 1;
                bic_bomb.receipt = eeh->m_services_id[eeh->m_id] + " 服务将在 1 秒内被销毁";
                
                std::string tomsg;
                bic_bomb.Serialize(&tomsg);

                uint16_t tomsgid = BIC_TYPE_S2P_BOMBER;
                uint64_t tosid = origin;

                send_message(tomsgid, tosid, tomsg, args);

                signal(SIGALRM, tcw::signal_release);
                alarm(2);
                Dbug(eeh->logger, FUNC, "pid %d would be destructed in 2 seconds", getpid());
            }
            break;
            default:
                Erro(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)msgid);
        }
    }

    return 0;
}