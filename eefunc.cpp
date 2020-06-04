
#include "eefunc.h"
#include "eehandler.h"
#include "bic.h"
#include "eehelper.h"
#include "eelog.h"

void* print_string(void* args)
{
    EEHNS::EpollEvHandler *eeh = (EEHNS::EpollEvHandler *)args;

    while (true) {
        ECHO(INFO, "now you in the print_string function...");
        /** lock it passively */
        std::unique_lock<std::mutex> lock(eeh->m_mutex);
        if (! eeh->m_cond.wait_for(lock, std::chrono::seconds(2), [&eeh](){ return ! eeh->m_messages.empty(); })) {
            /** 加个打印 */
            ECHO(INFO, "sid=%lu call wait_for the lock unlocked messages size=%lu", eeh->m_id, eeh->m_messages.size());
            continue;
        }
        
        ECHO(INFO, "======================================>wait it! deal with this message");
        
        std::string msg = std::move(eeh->m_messages.front());
        eeh->m_messages.pop();
        
        BIC_HEADER bich;
        BIC_MESSAGE bicm(&bich, nullptr);
        bicm.ExtractHeader(msg);
        
        BIC_BASE *tobicp = nullptr;
        BICTYPE totype{BIC_TYPE_NONE};
        
        if (bich.type == BIC_TYPE_P2S_SUMMON) {
            ECHO(INFO, "=================> message type is BIC_TYPE_P2S_SUMMON");
            BIC_SUMMON bic;
            BIC_MESSAGE bicsummon(nullptr, &bic);
            
            bicsummon.ExtractPayload(msg);
            
            EEHDBUG(eeh->logger, FUNC, "BIC_SUMMON.info:  %s", bic.info.c_str());
            EEHDBUG(eeh->logger, FUNC, "BIC_SUMMON.sno:   %s", bic.sno.c_str());
            EEHDBUG(eeh->logger, FUNC, "BIC_SUMMON.code:  %lu", bic.code);
            
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
        } else if (bich.type == BIC_TYPE_P2S_BITRON) {
            ECHO(INFO, "=================> message type is BIC_TYPE_P2S_BITRON");
            BIC_BITRON bic;
            BIC_MESSAGE bicbit(nullptr, &bic);
            
            bicbit.ExtractPayload(msg);
            
            EEHDBUG(eeh->logger, FUNC, "BIC_BITRON.bitslen: %d", bic.bitslen);
            uint32_t i;
            for (i = 0; i < bic.bitslen; ) {
                printf(" %02x", static_cast<int>((unsigned char)bic.bits[i]));
                if (++i % 16 == 0) printf("\n");
            }
            if (i % 16 != 0) printf("\n");
        } else if (bich.type == BIC_TYPE_P2S_BOMBER) {
            ECHO(INFO, "=================> message type is BIC_TYPE_P2S_BOMBER");
            BIC_BOMBER bic;
            BIC_MESSAGE bicbomb(nullptr, &bic);
            
            bicbomb.ExtractPayload(msg);
            
            EEHDBUG(eeh->logger, FUNC, "BIC_BOMBER.service_name: %s", bic.service_name.c_str());
            EEHDBUG(eeh->logger, FUNC, "BIC_BOMBER.service_type: %d", bic.service_type);
            EEHDBUG(eeh->logger, FUNC, "BIC_BOMBER.kill:         %s", bic.kill ? "true" : "false");
            
            BIC_BOMBER* bomb = new BIC_BOMBER();
            bomb->service_name = bic.service_name;
            bomb->service_type = bic.service_type;
            bomb->kill = bic.kill;
            bomb->rescode = 1;
            bomb->receipt = eeh->m_services_id[eeh->m_id] + " 服务将在 1 秒内被销毁";
            
            signal(SIGALRM, EEHNS::signal_release);
            alarm(2);
            EEHDBUG(eeh->logger, FUNC, "pid %d would be destructed in 2 seconds", getpid());
            
            tobicp = bomb;
            totype = BIC_TYPE_S2P_BOMBER;
        } else {
            EEHERRO(eeh->logger, FUNC, "undefined or unhandled msg(%d)", (int)bich.type);
        }
        
        if (totype == BIC_TYPE_NONE || ! tobicp) {
            continue;
        }
        
        EEHDBUG(eeh->logger, FUNC, "done! msg(type=%d) would send from(%s) to(%s)",
                    totype, eeh->m_services_id[eeh->m_id].c_str(), eeh->m_services_id[bich.origin].c_str());
        
        std::string tomsg;
        BIC_HEADER tobich(eeh->m_id, bich.origin, totype);
        BIC_MESSAGE tobicm(&tobich, tobicp);
        tobicm.Serialize(&tomsg);
        if (tomsg.empty()) {
            EEHWARN(eeh->logger, FUNC, "msg size is 0, but let's continue...");
            if (tobicp != nullptr) {
                delete tobicp;
            }
            return nullptr;     // for test
            // continue;        // for production
        }
        std::string tostream;
        add_header(&tostream, tomsg);
        if (tobicp != nullptr) {
            delete tobicp;
        }
        int tofd{0};
        if (eeh->m_pipe_pairs.find(eeh->m_id) != eeh->m_pipe_pairs.end()) {
            tofd = eeh->m_pipe_pairs[eeh->m_id].second;
        } else {
            EEHERRO(eeh->logger, FUNC, "an exception occurs");
            return nullptr;
        }
        
        EEHNS::BaseClient* tobc = dynamic_cast<EEHNS::BaseClient*>(eeh->m_clients[tofd]);
        if (! tobc) {
            EEHERRO(eeh->logger, FUNC, "could not find the client");
            return nullptr;
        }
        
        eeh->m_linker_queues[tobc->sid].push(tostream);
            
        EEHDBUG(eeh->logger, FUNC, "pushed msg(type=%d, len=%lu, from=%s) to que(ownby=%s, size=%lu) and forward to %s", 
                                    totype, tostream.size(), eeh->m_services_id[tobich.origin].c_str(),
                                    eeh->m_services_id[tobc->sid].c_str(), eeh->m_linker_queues[tobc->sid].size(),
                                    eeh->m_services_id[tobich.orient].c_str());
        
        eeh->EEH_mod(tobc, EPOLLOUT | EPOLLHUP | EPOLLRDHUP);
        ECHO(INFO, "-------------> alreadly deal with message");
    }

    return nullptr;
}