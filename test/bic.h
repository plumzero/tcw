
#ifndef __Basic_Instruction_Command_H__
#define __Basic_Instruction_Command_H__

#include <string>

class BIC_SUMMON
{
public:
    BIC_SUMMON() {}
    ~BIC_SUMMON() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string         info;
    std::string         sno;
    uint64_t            code;
};

class BIC_MONSTER
{
public:
    BIC_MONSTER() {}
    ~BIC_MONSTER() {}
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

class BIC_BITRON
{
public:
    BIC_BITRON() {}
    ~BIC_BITRON() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string     bits;
    uint32_t        bitslen;
};

class BIC_BLOCKRON
{
public:
    BIC_BLOCKRON() {}
    ~BIC_BLOCKRON() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string     fname;
    uint32_t        fsize;
    uint32_t        offset;
    uint32_t        blocksize;
    std::string     block;
};

class BIC_BOMBER
{
public:
    BIC_BOMBER() {}
    ~BIC_BOMBER() {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string     service_name;
    int32_t         service_type;
    bool            kill;
    int32_t         rescode;
    std::string     receipt;
};

class BIC_BETWEEN
{
public:
    BIC_BETWEEN() {}
    ~BIC_BETWEEN(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    std::string  from_service;
    std::string  to_service;
    std::string  information;
};

class BIC_P2P_START
{
public:
    BIC_P2P_START() {}
    ~BIC_P2P_START(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         is_start;
    std::string  information;
};


class BIC_A2A_START
{
public:
    BIC_A2A_START() {}
    ~BIC_A2A_START(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         is_start;
    std::string  information;
};

class BIC_A2B_BETWEEN
{
public:
    BIC_A2B_BETWEEN() {}
    ~BIC_A2B_BETWEEN(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         send;
    std::string  information;
};

class BIC_B2C_BETWEEN
{
public:
    BIC_B2C_BETWEEN() {}
    ~BIC_B2C_BETWEEN(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         send;
    std::string  information;
};


#endif // !__Basic_Instruction_Command_H__