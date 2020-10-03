
#pragma once

#include <string>

class MSG_A2A_START
{
public:
    MSG_A2A_START() {}
    ~MSG_A2A_START(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         is_start;
    std::string  information;
};

class MSG_A2B_BETWEEN
{
public:
    MSG_A2B_BETWEEN() {}
    ~MSG_A2B_BETWEEN(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         send;
    std::string  information;
};

class MSG_B2C_BETWEEN
{
public:
    MSG_B2C_BETWEEN() {}
    ~MSG_B2C_BETWEEN(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    bool         send;
    std::string  information;
};
