.PHONY: ALL clean

ALL: libmini.so libmini.a

libmini.so: libmini.c libmini64.asm libmini.h
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
	ld -shared -o libmini.so libmini64.o libmini.o

libmini.a: libmini.c libmini64.asm
	gcc -c -g -Wall -masm=intel -fno-stack-protector -fPIC -nostdlib libmini.c
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o
	ar rc libmini.a libmini64.o libmini.o

clean:
	rm -f *.o *.a *.so