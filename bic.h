
#ifndef __Basic_Instruction_Command_H__
#define __Basic_Instruction_Command_H__

#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include "raj.h"
#include "include.h"
#include "bic_type.h"

/*!
 *  version 1.0 带模板的版本，分离或进行类型转换时限制较多，抛弃；
 *  version 2.0 非模板版本，引用版本，当前版本；
 */

typedef _linker_or_server_type      BICORIGIN;      /** who sended this message */
typedef _linker_or_server_type      BICORIENT;      /** who would recv this message */

/********************************* 基类，消息头类，消息封装类 *********************************/

class BIC_BASE
{
public:
    // BIC_BASE(BICTYPE type) {  }
    virtual void Serialize(std::string *s) = 0;
    virtual void Structuralize(const std::string &s) = 0;
    BIC_BASE * getObject(BICTYPE type) { return this; }
public:
    BICTYPE t;
};

class BIC_HEADER : public BIC_BASE
{
public:
    BIC_HEADER(BICORIGIN from, BICORIENT to, BICTYPE t)
        : origin(from), orient(to), type(t), birth(time(NULL)) {}
    BIC_HEADER() 
      : origin(LINKER_TYPE_NONE), orient(LINKER_TYPE_NONE), type(BIC_TYPE_NONE), birth(time(NULL)) {}
    virtual ~BIC_HEADER() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    BICORIGIN origin;
    BICORIENT orient;
    BICTYPE   type;         // bodytype, pltype
    uint64_t  birth;
};

class BIC_MESSAGE
{
public:
    BIC_MESSAGE(BIC_HEADER *he, BIC_BASE *pl) : header(he), payload(pl) {}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
    void ExtractHeader(const std::string &s);
    void ExtractPayload(const std::string &s);
    
public:
    BIC_HEADER     *header;
    BIC_BASE       *payload;
};

/********************************* 消息类，由程序员定义 *********************************/

class BIC_GUARDRAGON : public BIC_BASE
{
public:
    BIC_GUARDRAGON() 
        : heartbeat(time(nullptr)), biubiu("Hello World") {}
    virtual ~BIC_GUARDRAGON() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    uint64_t        heartbeat;
    std::string     biubiu;
};

class BIC_SUMMON : public BIC_BASE
{
public:
    BIC_SUMMON() {}
    virtual ~BIC_SUMMON() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    std::string         info;
    std::string         sno;
    uint64_t            code;
};

class BIC_MONSTER : public BIC_BASE
{
public:
    BIC_MONSTER() {}
    virtual ~BIC_MONSTER() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
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

class BIC_BITRON : public BIC_BASE
{
public:
    BIC_BITRON() {}
    virtual ~BIC_BITRON() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    std::string     bits;
    uint32_t        bitslen;
};

class BIC_BLOCKRON : public BIC_BASE
{
public:
    BIC_BLOCKRON() {}
    virtual ~BIC_BLOCKRON() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    std::string     fname;
    uint32_t        fsize;
    uint32_t        offset;
    uint32_t        blocksize;
    std::string     block;
};

class BIC_BOMBER : public BIC_BASE
{
public:
    BIC_BOMBER() {}
    virtual ~BIC_BOMBER() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    std::string     service_name;
    int32_t         service_type;
    bool            kill;
    int32_t         rescode;
    std::string     receipt;
};

/********************************* 消息类型工厂类，非线程安全(暂不使用) *********************************/

class BIC_FACTORY
{
private:
    static std::map<BICTYPE, BIC_BASE*> bicmap;
public:
    static BIC_BASE* getObject(BICTYPE type);
};

#endif // !__Basic_Instruction_Command_H__