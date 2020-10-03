
#include "msg.h"
#include "raj.h"

void MSG_A2A_START::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "is_start",     this->is_start);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_A2A_START::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "is_start",     this->is_start);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_A2B_BETWEEN::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "send",         this->send);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_A2B_BETWEEN::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "send",         this->send);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_B2C_BETWEEN::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "send",         this->send);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_B2C_BETWEEN::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "send",         this->send);
    RAJ_parse_json(doc, "information",  this->information);
}
