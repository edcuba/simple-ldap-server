CXX ?= g++
CXXFLAGS ?= -Wall -O3
SRCS = src/*.cc
HDRS = src/*.h
TARGET = myldap
LIBS=-lpthread

$(TARGET): $(SRCS) $(HDRS)
	$(CXX) -std=c++14 $(CXXFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

clean:
	rm $(TARGET)
