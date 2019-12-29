
#include "bic.h"

/********************************* 基类，消息头类，消息封装类 *********************************/

void BIC_MESSAGE::Serialize(std::string *s)
{
	if (! header || ! payload) {
		return;
	}
	
	rapidjson::StringBuffer sb;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

	std::string sh;
	header->Serialize(&sh);

	std::string sp;
	payload->Serialize(&sp);

	writer.StartObject();
	
	RAJ_write_json(writer, "header", sh);
	RAJ_write_json(writer, "payload", sp);
	
	writer.EndObject();

	s->assign(sb.GetString(), sb.GetSize());
}
void BIC_MESSAGE::Structuralize(const std::string &s)
{
	if (! header || ! payload) {
		return;
	}
	
	rapidjson::Document doc;

	doc.Parse(s.c_str());
	
	std::string sh;
	std::string sp;
	if (! doc.HasMember("header") || ! doc.HasMember("payload")) {
		return;
	}
	
	RAJ_parse_json(doc, "header", sh);
	RAJ_parse_json(doc, "payload", sp);
		
	header->Structuralize(sh);
	payload->Structuralize(sp);
}
void BIC_MESSAGE::ExtractHeader(const std::string &s)
{
	rapidjson::Document doc;
	
	doc.Parse(s.c_str());
	
	std::string sh;
	if (! doc.HasMember("header")) {
		return;
	}
	
	RAJ_parse_json(doc, "header", sh);
	
	header->Structuralize(sh);
}
void BIC_MESSAGE::ExtractPayload(const std::string &s)
{
	rapidjson::Document doc;
	
	doc.Parse(s.c_str());

	std::string sp;
	if (! doc.HasMember("payload")) {
		return ;
	}
	
	RAJ_parse_json(doc, "payload", sp);
	
	payload->Structuralize(sp);
}

/********************************* 消息类，由程序员定义 *********************************/

void BIC_HEADER::Serialize(std::string *s)
{
	rapidjson::StringBuffer sb;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

	writer.StartObject();
	
	RAJ_write_json(writer, "origin", this->origin);
	RAJ_write_json(writer, "orient", this->orient);
	RAJ_write_json(writer, "type", this->type);
	RAJ_write_json(writer, "birth", this->birth);
	
	writer.EndObject();

	s->assign(sb.GetString(), sb.GetSize());
}

void BIC_HEADER::Structuralize(const std::string &s)
{
	rapidjson::Document doc;

	doc.Parse(s.c_str());

	RAJ_parse_json(doc, "origin", this->origin);
	RAJ_parse_json(doc, "orient", this->orient);
	RAJ_parse_json(doc, "type", this->type);
	RAJ_parse_json(doc, "birth", this->birth);
}

void BIC_GUARDRAGON::Serialize(std::string *s)
{
	rapidjson::StringBuffer sb;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);

	writer.StartObject();

	RAJ_write_json(writer, "heartbeat", this->heartbeat);
	RAJ_write_json(writer, "biubiu", this->biubiu);

	writer.EndObject();

	s->assign(sb.GetString(), sb.GetSize());
}

void BIC_GUARDRAGON::Structuralize(const std::string &s)
{
	rapidjson::Document doc;

	doc.Parse(s.c_str());
	
	RAJ_parse_json(doc, "heartbeat", this->heartbeat);
	RAJ_parse_json(doc, "biubiu", this->biubiu);
}

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

/********************************* 消息类型工厂类，非线程安全(暂不使用) *********************************/

std::map<BICTYPE, BIC_BASE*> BIC_FACTORY::bicmap = std::map<BICTYPE, BIC_BASE*>();

BIC_BASE* BIC_FACTORY::getObject(BICTYPE type)
{
	if (type == BIC_TYPE_GUARDRAGON) {
		bicmap[type] = new BIC_GUARDRAGON();
	} else {
		// ...
	}
	
	return bicmap[type];
}
