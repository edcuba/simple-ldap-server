#include "ber.h"

using namespace std;

/**
 * Encode length according to BER
 **/
string
encodeSize (size_t size)
{
    // FIXME size > 127
    string res;
    res += (char) size;
    return res;
}

/**
 * Encode integer according to BER
 **/
string
encodeInt (int i)
{
    // FIXME support > 127
    string res;
    res += (char) 0x02;
    res += (char) 1;
    res += (char) i;
    return res;
}

/**
 * Encode sequence according to BER
 **/
string
encodeSeq (const string &seq)
{
    string res;
    res += (char) 0x30;
    res += encodeSize (seq.size ());
    res += seq;
    return res;
}

/**
 * Encode string according to BER
 **/
string
encodeStr (const string &str)
{
    string res;
    res += (char) 0x04;
    res += encodeSize (str.size ());
    res += str;
    return res;
}

/**
 * Encode set according to BER
 **/
string
encodeSet (const string &set)
{
    string res;
    res += (char) 0x31;
    res += encodeSize (set.size ());
    res += set;
    return res;
}
