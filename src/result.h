#ifndef RESULT_H
#define RESULT_H

#include <string>

using namespace std;

typedef enum { RES_SUCCESS = 0 } ldapResultType;

static const string resultSucessData = { 0xA, 0x1, 0x0, 0x4, 0x0, 0x4, 0x0 };

/**
 * ldapResult class
 **/
class ldapResult
{
  public:
    ldapResult (ldapResultType t);
    ldapResultType type;
    const string dump () const;
};

#endif
