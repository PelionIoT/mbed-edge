# Makefile for gtests, dependencies failing currently so clean always

GOOGLE_TEST_LIB = gtest
GOOGLE_TEST_INCLUDE = /usr/local/include

G++ = g++
G++_FLAGS = -c -Wall -I $(GOOGLE_TEST_INCLUDE) -I ../../include/ -g
LD_FLAGS = -L /usr/local/lib -l $(GOOGLE_TEST_LIB) -l pthread

OBJECTS = tests.o
TARGET = tests

all: $(TARGET)

$(TARGET): $(OBJECTS)
	g++ -o $(TARGET) $(OBJECTS) $(LD_FLAGS)

%.o : %.cpp
	$(G++) $(G++_FLAGS) $<

clean:
	rm -f $(TARGET) $(OBJECTS)


.PHONY: test
test: clean all
	./tests
	
.PHONY: all clean