
#include "bic.h"
#include "raj.h"

void BIC_SUMMON::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "info", this->info);
    RAJ_write_json(writer, "sno", this->sno);
    RAJ_write_json(writer, "code", this->code);

    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_SUMMON::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "info", this->info);
    RAJ_parse_json(doc, "sno", this->sno);
    RAJ_parse_json(doc, "code", this->code);
}

void BIC_MONSTER::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "name", this->name);
    RAJ_write_json(writer, "type", this->type);
    RAJ_write_json(writer, "attribute", this->attribute);
    RAJ_write_json(writer, "race", this->race);
    RAJ_write_json(writer, "level", this->level);
    RAJ_write_json(writer, "attack", this->attack);
    RAJ_write_json(writer, "defense", this->defense);
    RAJ_write_json(writer, "description", this->description);

    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_MONSTER::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "name", this->name);
    RAJ_parse_json(doc, "type", this->type);
    RAJ_parse_json(doc, "attribute", this->attribute);
    RAJ_parse_json(doc, "race", this->race);
    RAJ_parse_json(doc, "level", this->level);
    RAJ_parse_json(doc, "attack", this->attack);
    RAJ_parse_json(doc, "defense", this->defense);
    RAJ_parse_json(doc, "description", this->description);
}

void BIC_BITRON::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "bits", this->bits);
    RAJ_write_json(writer, "bitslen", this->bitslen);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_BITRON::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "bits", this->bits);
    RAJ_parse_json(doc, "bitslen", this->bitslen);
}

void BIC_BLOCKRON::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "fname", this->fname);
    RAJ_write_json(writer, "fsize", this->fsize);
    RAJ_write_json(writer, "offset", this->offset);
    RAJ_write_json(writer, "blocksize", this->blocksize);
    RAJ_write_json(writer, "block", this->block);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_BLOCKRON::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "fname", this->fname);
    RAJ_parse_json(doc, "fsize", this->fsize);
    RAJ_parse_json(doc, "offset", this->offset);
    RAJ_parse_json(doc, "blocksize", this->blocksize);
    RAJ_parse_json(doc, "block", this->block);
}

void BIC_BOMBER::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "service_name", this->service_name);
    RAJ_write_json(writer, "service_type", this->service_type);
    RAJ_write_json(writer, "kill", this->kill);
    RAJ_write_json(writer, "rescode", this->rescode);
    RAJ_write_json(writer, "receipt", this->receipt);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_BOMBER::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "service_name", this->service_name);
    RAJ_parse_json(doc, "service_type", this->service_type);
    RAJ_parse_json(doc, "kill", this->kill);
    RAJ_parse_json(doc, "rescode", this->rescode);
    RAJ_parse_json(doc, "receipt", this->receipt);
}

void BIC_BETWEEN::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "from_service", this->from_service);
    RAJ_write_json(writer, "to_service",   this->to_service);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_BETWEEN::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "from_service", this->from_service);
    RAJ_parse_json(doc, "to_service",   this->to_service);
    RAJ_parse_json(doc, "information",  this->information);
}

void BIC_P2P_START::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "is_start",     this->is_start);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_P2P_START::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "is_start",     this->is_start);
    RAJ_parse_json(doc, "information",  this->information);
}

void BIC_A2A_START::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "is_start",     this->is_start);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_A2A_START::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "is_start",     this->is_start);
    RAJ_parse_json(doc, "information",  this->information);
}

void BIC_A2B_BETWEEN::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "send",         this->send);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_A2B_BETWEEN::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "send",         this->send);
    RAJ_parse_json(doc, "information",  this->information);
}

void BIC_B2C_BETWEEN::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "send",         this->send);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void BIC_B2C_BETWEEN::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "send",         this->send);
    RAJ_parse_json(doc, "information",  this->information);
}


