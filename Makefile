CC = g++
CFLAGS=-std=c++14
SRCS = myldap.cc

myldap: $(SRCS)
	$(CC) $(CFLAGS) $^ -o $@
