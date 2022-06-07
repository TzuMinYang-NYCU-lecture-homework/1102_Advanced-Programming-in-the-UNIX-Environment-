CXX = g++
CFLAGS = -Wall -g
LIBNAME = capstone

.PHONY: ALL clean

ALL: hw4

hw4: hw4.cpp
	$(CXX) -o $@ $? $(CFLAGS) -l$(LIBNAME)

clean:
	rm -f hw4