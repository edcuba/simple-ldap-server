#ifndef BER_H
#define BER_H

#include <cstring>
#include <string>

std::string
encodeInt (int i);

std::string
encodeSeq (const std::string &seq);

std::string
encodeStr (const std::string &str);

std::string
encodeSet (const std::string &set);

std::string
encodeSize (size_t size);

#endif
