
#pragma once

#include <string>

class MSG_P2P_START
{
public:
    MSG_P2P_START() {}
    ~MSG_P2P_START(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         is_start;
    std::string  information;
};

class MSG_SUMMON
{
public:
    MSG_SUMMON() {}
    ~MSG_SUMMON() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string         info;
    std::string         sno;
    uint64_t            code;
};

class MSG_MONSTER
{
public:
    MSG_MONSTER() {}
    ~MSG_MONSTER() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string         name;
    std::string         type;
    std::string         attribute;
    std::string         race;
    uint32_t            level;
    uint32_t            attack;
    uint32_t            defense;
    std::string         description;
};
