#ifndef RESULT_H
#define RESULT_H

#include <cstring>

using namespace std;

typedef enum { RES_SUCCESS = 0 } ldapResultType;

static const char resultSucessData[] = { 0xA, 0x1, 0x0, 0x4, 0x0, 0x4, 0x0 };

/**
 * ldapResult base abstract class
 **/
class ldapResult
{
  public:
    virtual const char *getData () const = 0;
    virtual const size_t getSize () const = 0;
};

/**
 * result success wrapper
 **/
class ldapResultSuccess : public ldapResult
{
  public:
    const char *getData () const { return resultSucessData; }
    const size_t getSize () const { return sizeof (resultSucessData); }
};

#endif
