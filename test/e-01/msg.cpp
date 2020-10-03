
#include "msg.h"
#include "raj.h"

void MSG_START::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "timestamp",    this->timestamp);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_START::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "timestamp",    this->timestamp);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_X2Y::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "count",        this->count);
    RAJ_write_json(writer, "timestamp",    this->timestamp);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_X2Y::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "count",        this->count);
    RAJ_parse_json(doc, "timestamp",    this->timestamp);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_Y2Z::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "count",        this->count);
    RAJ_write_json(writer, "timestamp",    this->timestamp);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_Y2Z::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "count",        this->count);
    RAJ_parse_json(doc, "timestamp",    this->timestamp);
    RAJ_parse_json(doc, "information",  this->information);
}

void MSG_Z2X::Serialize(std::string *s)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    writer.StartObject();

    RAJ_write_json(writer, "count",        this->count);
    RAJ_write_json(writer, "timestamp",    this->timestamp);
    RAJ_write_json(writer, "information",  this->information);
    
    writer.EndObject();

    s->assign(sb.GetString(), sb.GetSize());
}

void MSG_Z2X::Structuralize(const std::string &s)
{
    rapidjson::Document doc;

    doc.Parse(s.c_str());
    
    RAJ_parse_json(doc, "count",        this->count);
    RAJ_parse_json(doc, "timestamp",    this->timestamp);
    RAJ_parse_json(doc, "information",  this->information);
}
