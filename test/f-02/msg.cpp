
#include "msg.h"
#include "raj.h"

void MSG_P2P_START::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "is_start",     this->is_start);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_P2P_START::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "is_start",     this->is_start);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_SUMMON::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "info", this->info);
    RAJ_write_json(writer, "sno", this->sno);
    RAJ_write_json(writer, "code", this->code);

    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_SUMMON::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "info", this->info);
    RAJ_parse_json(doc, "sno", this->sno);
    RAJ_parse_json(doc, "code", this->code);
}

void MSG_MONSTER::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

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

void MSG_MONSTER::Structuralize(const std::string &s)
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
