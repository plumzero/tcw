
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

typedef uint64_t      BICORIGIN;      /** who sended this message */
typedef uint64_t      BICORIENT;      /** who would recv this message */

/********************************* 基类，消息头类，消息封装类 *********************************/

class BIC_BASE
{
public:
    virtual ~BIC_BASE() {}
    virtual void Serialize(std::string *s) = 0;
    virtual void Structuralize(const std::string &s) = 0;
};

class BIC_HEADER : public BIC_BASE
{
public:
    BIC_HEADER(BICORIGIN from, BICORIENT to, BICTYPE t)
        : origin(from), orient(to), type(t), birth(time(NULL)) {}
    BIC_HEADER() 
      : origin(0), orient(0), type(BIC_TYPE_NONE), birth(time(NULL)) {}
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

/**************************************** 测试类 ****************************************/

class BIC_TEST : public BIC_BASE
{
public:
    BIC_TEST() {}
    virtual ~BIC_TEST() {}
    virtual void Serialize(std::string *s);
    virtual void Structuralize(const std::string &s);
public:
    double                              d;
    std::string                         str;
    /** std::pair family */
    std::pair<int, int>                 pair_int_int;
    std::pair<int, std::string>         pair_int_str;
    std::pair<std::string, int>         pair_str_int;
    std::pair<std::string, std::string> pair_str_str;
    std::pair<std::string, std::pair<std::string, std::string> >    pair_str_pair_str_str;
    std::pair<std::string, std::vector<std::string> >               pair_str_vec_str;
    std::pair<std::string, std::map<std::string, std::string> >     pair_str_map_str_str;
    /// ... continue
    /** std::vector family */
    std::vector<int>                    vec_int;
    std::vector<std::string>            vec_str;
    std::vector<std::pair<int, int> >                               vec_pair_int_int;
    std::vector<std::pair<std::string, std::string> >               vec_pair_str_str;
    std::vector<std::vector<std::string> >                          vec_vec_str;
    std::vector<std::map<std::string, std::string> >                vec_map_str_str;
    /// ... continue
    /** std::map family */
    std::map<int, int>                  map_int_int;
    std::map<int, std::string>          map_int_str;
    std::map<std::string, int>          map_str_int;
    std::map<std::string, std::string>  map_str_str;
    std::map<int, std::vector<int> >                                map_int_vec_int;
    std::map<std::string, std::pair<std::string, std::string> >     map_str_pair_str_str;
    std::map<std::string, std::vector<std::string> >                map_str_vec_str;
    std::map<int, std::map<int, int> >                              map_int_map_int_int;
    /// ... continue
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