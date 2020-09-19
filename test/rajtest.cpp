
#include "include.h"
#include "bic.h"
#include <rapidjson/raj.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <list>
#include <set>
#include <map>
#include <type_traits>

/**!
 *  编译: g++ -g rajtest.cpp bic.cpp -o rajtest -std=c++11
 *  执行: ./rajtest
 */
// pair<T, V>
template<typename T, typename V>
static void traverse_pair_T_V(std::pair<T, V>& data)
{
    std::cout << "  ";
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << data.first;
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << " : ";
    if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
    std::cout << data.second;
    if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
    std::cout << "  " << std::endl;
}
// pair<K, pair<T, V>>
template<typename K, typename T, typename V>
static void traverse_pair_K_pair_T_V(std::pair<K, std::pair<T, V> >& data)
{
    std::cout << "  ";
    if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
    std::cout << data.first;
    if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
    std::cout << " : { ";
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << data.second.first;
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << " : ";
    if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
    std::cout << data.second.second;
    if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
    std::cout << "}" << std::endl;
}
// pair<T, vector<V>>
template<typename T, typename V>
static void traverse_pair_T_vec_V(std::pair<T, std::vector<V> >& data)
{
    std::cout << "  ";
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << data.first;
    if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
    std::cout << " : [ ";
    for (typename std::vector<V>::iterator it = data.second.begin(); it != data.second.end(); it++) {
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << *it;
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << ", ";
    }
    std::cout << " ]" << std::endl;
}
// pair<T, map<T, V>>
template<typename K, typename T, typename V>
static void traverse_pair_K_map_T_V(std::pair<K, std::map<T, V> >& data)
{
    std::cout << "  ";
    if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
    std::cout << data.first;
    if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
    std::cout << " : { ";
    for (typename std::map<T, V>::iterator it = data.second.begin(); it != data.second.end(); it++) {
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << ":";
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << it->second;
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << ", ";
    }
    std::cout << " }" << std::endl;
}

// vector<T>
template<typename T>
static void traverse_vec_T(std::vector<T>& data)
{
    std::cout << "  [ ";
    for (typename std::vector<T>::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout  << *it;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        if (it + 1 != data.end()) std::cout << ", ";
    }
    std::cout << " ]" << std::endl;
}
// vector<pair<T, V> >
template<typename T, typename V>
static void traverse_vec_pair_T_V(std::vector<std::pair<T, V> >& data)
{
    std::cout << "  [ ";
    for (typename std::vector<std::pair<T, V> >::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << ":";
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << it->second;
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        if (it + 1 != data.end()) std::cout << ", ";
    }
    std::cout << " ]" << std::endl;
}
// vector<vector<T>>
template<typename T>
static void traverse_vec_vec_T(std::vector<std::vector<T> >& data)
{
    std::cout << "  [ ";
    for (typename std::vector<std::vector<T> >::iterator it = data.begin(); it != data.end(); it++) {
        std::cout << " [ ";
        for (typename std::vector<T>::iterator itr = it->begin(); itr != it->end(); itr++) {
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << *itr;
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << ", ";
        }
        std::cout << " ], ";
    }
    std::cout << " ]" << std::endl;
}
// vector<map<T, V>>
template<typename T, typename V>
static void traverse_vec_map_T_V(std::vector<std::map<T, V> >& data)
{
    std::cout << "  [ ";
    for (typename std::vector<std::map<T, V> >::iterator it = data.begin(); it != data.end(); it++) {
        std::cout << " { ";
        for (typename std::map<T, V>::iterator itr = it->begin(); itr != it->end(); itr++) {
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << itr->first;
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << ":";
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            std::cout << itr->second;
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            std::cout << ", ";
        }
        std::cout << " }, ";
    }
    std::cout << " ]" << std::endl;
}
// map<T, V>
template<typename T, typename V>
static void traverse_map_T_V(std::map<T, V>& data)
{
    std::cout << "  { ";
    for (typename std::map<T, V>::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << ":";
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << it->second;
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << ", ";
    }
    std::cout << " }" << std::endl;
}
// map<K, pair<T, V> >
template <typename K, typename T, typename V>
static void traverse_map_K_pair_T_V(std::map<K, std::pair<T, V> >& data)
{
    std::cout << "  { ";
    for (typename std::map<K, std::pair<T, V> >::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
        std::cout << ":{ ";
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << it->second.first;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << ":";
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << it->second.second;
        if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
        std::cout << " }, ";
    }
    std::cout << " }" << std::endl;
}
// map<T, vector<V> >
template<typename T, typename V>
static void traverse_map_T_vec_V(std::map<T, std::vector<V> >& data)
{
    std::cout << "  { ";
    for (typename std::map<T, std::vector<T> >::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
        std::cout << ":[";
        for (typename std::vector<V>::iterator itr = it->second.begin(); itr != it->second.end(); itr++) {
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            std::cout << *itr;
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            if (itr + 1 != it->second.end()) std::cout << ",";
        }
        std::cout << "], ";
    }
    std::cout << " }" << std::endl;
}
// map<K, map<T, V> >
template<typename K, typename T, typename V>
static void traverse_map_K_map_T_V(std::map<K, std::map<T, V> >& data)
{
    std::cout << "  { ";
    for (typename std::map<K, std::map<T, V> >::iterator it = data.begin(); it != data.end(); it++) {
        if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
        std::cout << it->first;
        if (std::is_same<typename std::decay<K>::type, std::string>::value) std::cout << "\"";
        std::cout << ":{ ";
        for (typename std::map<T, V>::iterator itr = it->second.begin(); itr != it->second.end(); itr++) {
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << itr->first;
            if (std::is_same<typename std::decay<T>::type, std::string>::value) std::cout << "\"";
            std::cout << ":";
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            std::cout << itr->second;
            if (std::is_same<typename std::decay<V>::type, std::string>::value) std::cout << "\"";
            std::cout << ", ";
        }
        std::cout << " }, ";
    }
    std::cout << " }" << std::endl;
}

#define LINKER_TYPE_POLICY      0x1234
#define LINKER_TYPE_MADOLCHE    0x5678

int main()
{
    /******************** 开始测试 ********************/
    DBUG("======================================= serialize header ======================================");
    BIC_HEADER bic_h(LINKER_TYPE_POLICY, LINKER_TYPE_MADOLCHE, BIC_TYPE_GUARDRAGON);
    std::string str_header;
    bic_h.Serialize(&str_header);
    DBUG("%s", str_header.c_str());
    
    DBUG("======================================= serialize body ========================================");
    BIC_TEST bic_a;
    bic_a.d = 123456789.987654321;
    bic_a.str.assign("hello world");
    /** std::pair<int, int> */
    bic_a.pair_int_int.first = 100;
    bic_a.pair_int_int.second = 1000;
    /** std::pair<int, std::string> */
    bic_a.pair_int_str.first = 100;
    bic_a.pair_int_str.second = "one hundred";
    /** std::pair<std::string, int> */
    bic_a.pair_str_int.first = "one hundred";
    bic_a.pair_str_int.second = 100;
    /** std::pair<std::string, std::string> */
    bic_a.pair_str_str.first = "key parameter";
    bic_a.pair_str_str.second = "value parameter";
    /** std::pair<std::string, std::pair<std::string, std::string>> */
    bic_a.pair_str_pair_str_str = std::make_pair("hello key", std::pair<std::string, std::string>("world key", "world value"));
    /** std::pair<std::string, std::vector<std::string>> */
    std::vector<std::string> pair_vec_str_help;
    pair_vec_str_help.push_back("hello world");
    pair_vec_str_help.push_back("hello kitty");
    pair_vec_str_help.push_back("hello HanMeiMei");
    bic_a.pair_str_vec_str = std::make_pair("hello What ?", pair_vec_str_help);
    /** std::pair<std::string, std::map<std::string, std::string>> */
    std::map<std::string, std::string> pair_map_str_str_help;
    pair_map_str_str_help["the first line"] = "From fairest creatures we desire increase,";
    pair_map_str_str_help["the second line"] = "That thereby beauty's rose might never die,";
    pair_map_str_str_help["the third line"] = "But as the riper should by time decease,";
    bic_a.pair_str_map_str_str = std::make_pair("sonnet poetry", pair_map_str_str_help);
    /** std::vector<int> */
    bic_a.vec_int.push_back(100);
    bic_a.vec_int.push_back(200);
    bic_a.vec_int.push_back(300);
    bic_a.vec_int.push_back(400);
    /** std::vector<std::string> */
    bic_a.vec_str.push_back("light red");
    bic_a.vec_str.push_back("orange");
    bic_a.vec_str.push_back("egg yellow");
    bic_a.vec_str.push_back("green");
    bic_a.vec_str.push_back("cyan");
    bic_a.vec_str.push_back("orange");
    bic_a.vec_str.push_back("deep blue");
    bic_a.vec_str.push_back("egg yellow");
    bic_a.vec_str.push_back("purple");
    /** std::vector<std::pair<int, int>> */
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(1, 4880));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(2, 4880));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(4, 12756));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(3, 6796));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(8, 142984));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(7, 120536));
    bic_a.vec_pair_int_int.push_back(std::pair<int, int>(6, 51118));
    bic_a.vec_pair_int_int.push_back(std::make_pair(5, 49576));
    /** std::vector<std::pair<std::string, std::string>> */
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("one planet", "little Mercury"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("two planet", "little Venus"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("four planet", "middle Earth"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("three planet", "little Mars"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("eight planet", "large Jupiter"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("seven planet", "large Saturn"));
    bic_a.vec_pair_str_str.push_back(std::pair<std::string, std::string>("six planet", "middle Uranus"));
    /** std:vector<std::vector<std::string>> */
    std::vector<std::string> vec_vec_str_help1;
    std::vector<std::string> vec_vec_str_help2;
    std::vector<std::string> vec_vec_str_help3;
    vec_vec_str_help1.push_back("red color");
    vec_vec_str_help1.push_back("green color");
    vec_vec_str_help1.push_back("blue color");
    vec_vec_str_help2.push_back("big size");
    vec_vec_str_help2.push_back("middle size");
    vec_vec_str_help2.push_back("little size");
    vec_vec_str_help3.push_back("good");
    vec_vec_str_help3.push_back("bad");
    vec_vec_str_help3.push_back("just so so");
    bic_a.vec_vec_str.push_back(vec_vec_str_help1);
    bic_a.vec_vec_str.push_back(vec_vec_str_help2);
    bic_a.vec_vec_str.push_back(vec_vec_str_help3);
    /** std::vector<std::map<std::string, std::string>> */
    std::map<std::string, std::string> vec_map_str_str_help1;
    std::map<std::string, std::string> vec_map_str_str_help2;
    vec_map_str_str_help1["color one"] = "this is red color";
    vec_map_str_str_help1["color two"] = "this is red color, too";
    vec_map_str_str_help1["color three"] = "this is green color";
    vec_map_str_str_help2["size one"] = "this is big size";
    vec_map_str_str_help2["size two"] = "this is little size";
    bic_a.vec_map_str_str.push_back(vec_map_str_str_help1);
    bic_a.vec_map_str_str.push_back(vec_map_str_str_help2);
    /** std::map<int, int> */
    bic_a.map_int_int[1] = 100;
    bic_a.map_int_int[2] = 200;
    bic_a.map_int_int[3] = 300;
    /** std::map<int, std::string> */
    bic_a.map_int_str[11] = "hello eleven";
    bic_a.map_int_str[12] = "hello twelve";
    bic_a.map_int_str[13] = "hello thirteen";
    /** std::map<std::string, int> */
    bic_a.map_str_int["one level"] = 1;
    bic_a.map_str_int["two level"] = 2;
    bic_a.map_str_int["three level"] = 3;
    /** std::map<std::string, std::string> */
    std::map<std::string, std::string> map_str_str;
    bic_a.map_str_str["little planet"] = "orange Mars";
    bic_a.map_str_str["middle planet"] = "blue Earth";
    bic_a.map_str_str["large planet"] = "brown Jupiter";
    /** std::map<std::string, std::pair<std::string, std::string> > */
    bic_a.map_str_pair_str_str.insert(std::make_pair("one key", std::pair<std::string, std::string>("pair key part", "pair value part")));
    bic_a.map_str_pair_str_str.insert(std::make_pair("two key", std::pair<std::string, std::string>("pair key part", "pair value part")));
    bic_a.map_str_pair_str_str.insert(std::make_pair("three key", std::pair<std::string, std::string>("pair key part", "pair value part another")));
    bic_a.map_str_pair_str_str.insert(std::make_pair("four key", std::pair<std::string, std::string>("pair key part another", "pair value part")));
    bic_a.map_str_pair_str_str.insert(std::make_pair("five key", std::pair<std::string, std::string>("pair key part another", "pair value part another")));
    /** std::map<int, std::vector<int>> */
    int map_int_vec_int_help[] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    std::vector<int> map_int_vec_int_help1(map_int_vec_int_help, map_int_vec_int_help + 5), map_int_vec_int_help2(map_int_vec_int_help + 3, map_int_vec_int_help + 9);
    bic_a.map_int_vec_int[2] = map_int_vec_int_help1;
    bic_a.map_int_vec_int[32] = map_int_vec_int_help2;
    /** std::map<std::string, std::vector<std::string> > */
    std::map<std::string, std::vector<std::string> > map_str_vec_str;
    const char *map_str_vec_str_help[] = { "one", "one", "three three", "three three", "five five", "five", "seven seven", "seven seven", "nine", "nine" };
    std::vector<std::string> map_str_vec_str_help1(map_str_vec_str_help, map_str_vec_str_help + 5), map_str_vec_str_help2(map_str_vec_str_help + 3, map_str_vec_str_help + 9);
    bic_a.map_str_vec_str["digit key one"] = map_str_vec_str_help1;
    bic_a.map_str_vec_str["digit key two"] = map_str_vec_str_help2;
    /** std::map<int, std::map<int, int>> */
    std::map<int, int> map_int_map_int_int_help1, map_int_map_int_int_help2;
    map_int_map_int_int_help1[2] = 3;
    map_int_map_int_int_help1[3] = 4;
    map_int_map_int_int_help1[4] = 5;
    map_int_map_int_int_help2[12] = 13;
    map_int_map_int_int_help2[13] = 14;
    map_int_map_int_int_help2[14] = 15;
    bic_a.map_int_map_int_int[1] = map_int_map_int_int_help1;
    bic_a.map_int_map_int_int[11] = map_int_map_int_int_help2;

    std::string str_body;
    bic_a.Serialize(&str_body);
    DBUG("%s", str_body.c_str());
    DBUG("===================================== serialize total =====================================");
    BIC_MESSAGE bic_m(&bic_h, &bic_a);
    
    std::string str_total;
    bic_m.Serialize(&str_total);
    DBUG("%s", str_total.c_str());


    DBUG("==================================== structralize header ===================================");
    BIC_HEADER     header;
    BIC_TEST payload;
    BIC_MESSAGE bic_m_c(nullptr, &payload);
    // bic_m_c.ExtractHeader(str_total);
    bic_m_c.ExtractPayload(str_total);
    
    // bic_m_c.Structuralize(str_total);
    
    std::cout << "BICORIGIN: origin = " << header.origin << std::endl;
    std::cout << "BICORIENT: orient = " << header.orient << std::endl;
    std::cout << "BICTYPE: type = " << header.type << std::endl;
    std::cout << "uint64_t: birth = " << header.birth << std::endl;
    
    DBUG("===================================== structralize body ====================================");
    std::cout << "double:       d = " << payload.d << std::endl;
    std::cout << "std::string:  str = " << payload.str << std::endl;
    std::cout << "std::pair<int, int>: " << std::endl;
    traverse_pair_T_V(payload.pair_int_int);
    std::cout << "std::pair<int, std::string>: " << std::endl;
    traverse_pair_T_V(payload.pair_int_str);
    std::cout << "std::pair<std::string, int>: " << std::endl;
    traverse_pair_T_V(payload.pair_str_int);
    std::cout << "std::pair<std::string, std::string>: " << std::endl;
    traverse_pair_T_V(payload.pair_str_str);
    std::cout << "std::pair<std::string, std::pair<std::string, std::string>>: " << std::endl;
    traverse_pair_K_pair_T_V(payload.pair_str_pair_str_str);
    std::cout << "std::pair<std::string, std::vector<std::string>>: " << std::endl;
    traverse_pair_T_vec_V(payload.pair_str_vec_str);
    std::cout << "std::pair<std::string, std::map<std::string, std::string>>: " << std::endl;
    traverse_pair_K_map_T_V(payload.pair_str_map_str_str);

    std::cout << "std::vector<int>: " << std::endl;
    traverse_vec_T(payload.vec_int);
    std::cout << "std::vector<std::string>: " << std::endl;
    traverse_vec_T(payload.vec_str);
    std::cout << "std::vector<std::pair<int, int>>: " << std::endl;
    traverse_vec_pair_T_V(payload.vec_pair_int_int);
    std::cout << "std::vector<std::pair<std::string, std::string>>: " << std::endl;
    traverse_vec_pair_T_V(payload.vec_pair_str_str);
    std::cout << "std::vector<std::vector<std::string>>:" << std::endl;
    traverse_vec_vec_T(payload.vec_vec_str);
    std::cout << "std::vector<std::map<std::string, std::string>>:" << std::endl;
    traverse_vec_map_T_V(payload.vec_map_str_str);

    std::cout << "std::map<int, int>:" << std::endl;
    traverse_map_T_V(payload.map_int_int);
    std::cout << "std::map<int, std::string>:" << std::endl;
    traverse_map_T_V(payload.map_int_str);
    std::cout << "std::map<std::string, int>:" << std::endl;
    traverse_map_T_V(payload.map_str_int);
    std::cout << "std::map<std::string, std::string>:" << std::endl;
    traverse_map_T_V(payload.map_str_str);
    std::cout << "std::map<std::string, std::pair<std::string, std::string> >" << std::endl;
    traverse_map_K_pair_T_V(payload.map_str_pair_str_str);
    std::cout << "std::map<int, std::vector<int>>:" << std::endl;
    traverse_map_T_vec_V(payload.map_int_vec_int);
    std::cout << "std::map<std::string, std::vector<std::string>>:" << std::endl;
    traverse_map_T_vec_V(payload.map_str_vec_str);
    std::cout << "std::map<int, std::map<int, int>>:" << std::endl;
    traverse_map_K_map_T_V(payload.map_int_map_int_int);

    DBUG("===========================================================================================");

    return 0;
}