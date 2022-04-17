CXX = gcc
CFLAGS = -Wall -shared -fPIC -ldl #!!! 不知道why把-ldl放在中間的話會link不到, 造成sο檔有問題

logger.so: hw2.c
	$(CXX) -o $@ $? $(CFLAGS)