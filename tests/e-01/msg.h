
#pragma once

#include <string>

class MSG_START
{
public:
    MSG_START() {}
    ~MSG_START(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    uint64_t     timestamp;
    std::string  information;
};

class MSG_X2Y
{
public:
    MSG_X2Y() {}
    ~MSG_X2Y(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    int          count;
    uint64_t     timestamp;
    std::string  information;
};

class MSG_Y2Z                                                                                                              
{
public:
    MSG_Y2Z() {}
    ~MSG_Y2Z(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    int          count;
    uint64_t     timestamp;
    std::string  information;
};

class MSG_Z2X
{
public:
    MSG_Z2X() {}
    ~MSG_Z2X(){}
    void Serialize(std::string *s);
    void Structuralize(const std::string &s);
public:
    int          count;
    uint64_t     timestamp;
    std::string  information;
};
