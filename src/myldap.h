#ifndef MYLDAP_H
#define MYLDAP_H

#define DEBUG false

#define EXPECT(data, val, err)                                                               \
    if (data != val) {                                                                       \
        printE ("expected: 0x" << std::hex << val << ", got: 0x" << std::hex << (int) data); \
        return ldapMessage (err);                                                            \
    }

#define EXPECT_RANGE(data, from, to, err)                                                      \
    if (data < from || data > to) {                                                            \
        printE ("expected <" << from << ", " << to << ">, got: 0x" << std::hex << (int) data); \
        return ldapMessage (err);                                                              \
    }

#endif
