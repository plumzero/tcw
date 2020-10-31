
#ifndef __RAJ_WRITER_PARSER_JSON_H__
#define __RAJ_WRITER_PARSER_JSON_H__

#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include <string>
#include <vector>
#include <list>
#include <map>
#include <iostream>
#include <sstream>
#include <type_traits>

/****************************************  for RAJ_write_json ****************************************/

/** forward declaration */
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::string& name, const T& val);
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const T& val, const std::false_type&, const std::false_type&);
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const T& val, const std::true_type&, const std::false_type&);
template <typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::string& val, const std::true_type&, const std::true_type&);
/** help function */
template <typename T>
static std::string RAJ_get_string(T value)
{
    std::stringstream ss;
    ss << value;
    return ss.str();
}
/** deal with std::vector */
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::vector<T>& val)
{
    writer.StartArray();

    for (typename std::vector<T>::const_iterator it = val.begin(); it != val.end(); it++) {
        RAJ_write_json(writer, *it, std::is_class<T>(), std::is_base_of<std::string, T>());
    }

    writer.EndArray();
}
/** deal with std::pair */
template <typename K, typename V, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::pair<K, V>& val)
{
    writer.StartObject();

    RAJ_write_json(writer, RAJ_get_string(val.first), val.second);

    writer.EndObject();
}
/** deal with std::map */
template <typename K, typename V, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::map<K, V>& val)
{
    writer.StartObject();

    for (typename std::map<K, V>::const_iterator it = val.begin(); it != val.end(); it++) {
        RAJ_write_json(writer, RAJ_get_string(it->first), it->second);
    }

    writer.EndObject();
}
/** fundmental type */
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const T& val, const std::false_type&, const std::false_type&)
{
    /** just only deal with the type rapidjson supported(defined in writer.h) */
    if (std::is_same<typename std::decay<T>::type, bool>::value) {
        writer.Bool(static_cast<bool>(val));
    } else if (std::is_same<typename std::decay<T>::type, int>::value) {
        writer.Int(static_cast<int>(val));
    } else if (std::is_same<typename std::decay<T>::type, unsigned int>::value) {
        writer.Uint(static_cast<unsigned int>(val));
    } else if (std::is_same<typename std::decay<T>::type, int64_t>::value) {
        writer.Int64(static_cast<int64_t>(val));
    } else if (std::is_same<typename std::decay<T>::type, uint64_t>::value) {
        writer.Uint64(static_cast<uint64_t>(val));
    } else if (std::is_same<typename std::decay<T>::type, double>::value) {
        writer.Double(static_cast<double>(val));
    } else if (std::is_enum<T>::value) {
        writer.Int(static_cast<int>(val));
    } else {
        std::cerr << "unsupport type" << std::endl;
    }

    return;
}
/** containers ... */
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const T& val, const std::true_type&, const std::false_type&)
{
    return RAJ_write_json(writer, val);
}
/** deal with std::string */
template <typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::string& val, const std::true_type&, const std::true_type&)
{
    writer.String(val.c_str(), static_cast<rapidjson::SizeType>(val.size()));
}
/** internal raj write interface for BIC calling */
template <typename T, typename OutputStream = rapidjson::StringBuffer>
void RAJ_write_json(rapidjson::Writer<OutputStream>& writer, const std::string& name, const T& val)
{
    writer.String(name.c_str());
    /** deferred compilation mechanism */
    return RAJ_write_json(writer, val, std::is_class<T>(), std::is_base_of<std::string, T>());
}

/****************************************  for RAJ_parse_json ****************************************/

/** forward declaration */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::GenericDocument<Encoding>& doc, const std::string& name, T& val);
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::false_type&, const std::false_type&);
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::true_type&, const std::true_type&);
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::true_type&, const std::false_type&);
/** help function */
template <typename otype, typename itype>
static otype RAJ_get_value(itype input)
{
    otype output;
    memcpy(&output, (void*)&input, sizeof(input));
    return output;
}
/** internal raj parse interface for BIC calling */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::GenericDocument<Encoding>& doc, const std::string& name, T& val)
{
    /** anomaly detection */
    if (doc.HasMember(name.c_str()))
        return RAJ_parse_json(doc[name.c_str()], val, std::is_class<T>(), std::is_base_of<std::string, T>());
}
/** fundmental type */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::false_type&, const std::false_type&)
{
    rapidjson::Value& rjs = rjval;

    if (std::is_same<typename std::decay<T>::type, bool>::value) {
        if (rjval.IsString()) {
            rjs.SetBool(static_cast<bool>(atoi(std::string(rjval.GetString()).c_str())));
        }
        val = RAJ_get_value<T>(rjs.GetBool());
    } else if (std::is_same<typename std::decay<T>::type, int>::value) {
        if (rjval.IsString()) {
            rjs.SetInt(static_cast<int>(atoi(std::string(rjval.GetString()).c_str())));
        }
        val = RAJ_get_value<T>(rjs.GetInt());
    } else if (std::is_same<typename std::decay<T>::type, unsigned int>::value) {
        if (rjval.IsString()) {
            rjs.SetUint(static_cast<unsigned int>(atoi(std::string(rjval.GetString()).c_str())));
        }
        val = RAJ_get_value<T>(rjs.GetUint());
    } else if (std::is_same<typename std::decay<T>::type, int64_t>::value) {
        if (rjval.IsString()) {
            rjs.SetInt64(static_cast<int64_t>(strtoll(std::string(rjval.GetString()).c_str(), NULL, 0)));
        }
        val = RAJ_get_value<T>(rjs.GetInt64());
    } else if (std::is_same<typename std::decay<T>::type, uint64_t>::value) {
        if (rjval.IsString()) {
            rjs.SetUint64(static_cast<uint64_t>(strtoull(std::string(rjval.GetString()).c_str(), NULL, 0)));
        }
        val = RAJ_get_value<T>(rjs.GetUint64());
    } else if (std::is_same<typename std::decay<T>::type, double>::value) {
        if (rjval.IsString()) {
            rjs.SetDouble(static_cast<double>(strtod(std::string(rjval.GetString()).c_str(), NULL)));
        }
        val = RAJ_get_value<T>(rjs.GetDouble());
    } else if (std::is_enum<T>::value) {
        if (rjval.IsString()) {
            rjs.SetInt(static_cast<int>(atoi(std::string(rjval.GetString()).c_str())));
        }
        val = static_cast<T>(RAJ_get_value<T>(rjs.GetInt()));
    } else {
        std::cerr << "unsupport type" << std::endl;
    }

    return;
}
/** deal with std::string */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::true_type&, const std::true_type&)
{
    val = std::string(rjval.GetString(), rjval.GetStringLength());
}
/** deal with std::vector */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, std::vector<T>& val)
{
    val.clear();
    rapidjson::SizeType i;
    for (i = 0; i < rjval.Size(); i++) {
        T t;
        RAJ_parse_json(rjval[i], t, std::is_class<T>(), std::is_base_of<std::string, T>());
        val.push_back(t);
    }
}
/** deal with std::pair */
template <typename K, typename V, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, std::pair<K, V>& val)
{
    std::pair<K, V> empty_pair;
    val.swap(empty_pair);
    rapidjson::Value::MemberIterator itr = rjval.MemberBegin();
    K k;
    RAJ_parse_json(itr->name, k, std::is_class<K>(), std::is_base_of<std::string, K>());
    V v;
    RAJ_parse_json(itr->value, v, std::is_class<V>(), std::is_base_of<std::string, V>());
    val = std::make_pair(k, v);
}
/** deal with std::map */
template <typename K, typename V, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, std::map<K, V>& val)
{
    val.clear();
    rapidjson::Value::MemberIterator itr;
    for (itr = rjval.MemberBegin(); itr != rjval.MemberEnd(); itr++) {
        K k;
        RAJ_parse_json(itr->name, k, std::is_class<K>(), std::is_base_of<std::string, K>());
        V v;
        RAJ_parse_json(itr->value, v, std::is_class<V>(), std::is_base_of<std::string, V>());
        val[k] = v;
    }
}
/* containers ... */
template <typename T, typename Encoding = rapidjson::UTF8<> >
void RAJ_parse_json(rapidjson::Value& rjval, T& val, const std::true_type&, const std::false_type&)
{
    return RAJ_parse_json(rjval, val);
}

#endif  // !__RAJ_WRITER_PARSER_JSON_H__