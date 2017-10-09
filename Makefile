CC = g++
CFLAGS=-std=c++14 -O0 -g
SRCS = src/*.cc
HDRS = src/*.h
TARGET = myldap
LIBS=-lpthread

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

clean:
	rm $(TARGET)
