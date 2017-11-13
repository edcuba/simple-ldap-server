CXX ?= g++
CXXFLAGS ?= -Wall -O3
SRCS = src/*.cc
HDRS = src/*.h
TARGET = myldap
LIBS = -lpthread

DOCS = docs/manual.tex manual.pdf
STATIC = static/example.csv
MISC = .clang-format LICENSE Makefile README.md

ARCHIVE = xcubae00.tar

$(TARGET): $(SRCS) $(HDRS)
	$(CXX) -std=c++14 $(CXXFLAGS) $(LDFLAGS) $(LIBS) $^ -o $@

clean:
	rm -f $(TARGET) $(ARCHIVE)

pack:
	cp docs/manual.pdf .
	tar -cf ${ARCHIVE} ${SRCS} ${HDRS} ${DOCS} ${STATIC} ${MISC}
