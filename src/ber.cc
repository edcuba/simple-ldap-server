#include "ber.h"

using namespace std;

/**
 * Encode length according to BER
 **/
string
encodeSize (size_t size)
{
    string res;
    if (size < 0x80) {
        res += (char) size;
    } else {
        size_t o4 = (size >> 24) & 0xFF;
        size_t o3 = (size >> 16) & 0xFF;
        size_t o2 = (size >> 8) & 0xFF;
        size_t o1 = size & 0xFF;
        char bytes = 4;
        if (o4 == 0) {
            bytes--;
            if (o3 == 0) {
                bytes--;
                if (o2 == 0) {
                    bytes--;
                }
            }
        }
        res += (char) 0x80 + bytes;
        if (bytes == 4) {
            res += (char) o4;
        }
        if (bytes >= 3) {
            res += (char) o3;
        }
        if (bytes >= 2) {
            res += (char) o2;
        }
        res += (char) o1;
    }
    return res;
}

/**
 * Encode integer according to BER
 **/
string
encodeInt (int i)
{
    string res;
    res += (char) 0x02;

    int o4 = (i >> 24) & 0xFF;
    int o3 = (i >> 16) & 0xFF;
    int o2 = (i >> 8) & 0xFF;
    int o1 = i & 0xFF;

    char bytes = 4;
    if (o4 == 0 || o4 == 1) {
        bytes--;
        if (o3 == 0 || o3 == 1) {
            bytes--;
            if (o2 == 0 || o2 == 1) {
                bytes--;
            }
        }
    }
    res += bytes;

    if (bytes == 4) {
        res += (char) o4;
    }
    if (bytes >= 3) {
        res += (char) o3;
    }
    if (bytes >= 2) {
        res += (char) o2;
    }
    res += (char) o1;

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
