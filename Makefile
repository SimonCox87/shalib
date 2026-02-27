CFLAGS = -g -Wall -fdiagnostics-color=always -Iinclude -O3 -march=native

test: test.o sha256.o sha_common.o
	cc $(CFLAGS) -o test test.o sha256.o sha_common.o
	
test.o: tests/test.c include/sha.h 
	cc $(CFLAGS) -c tests/test.c -o test.o

sha256.o: src/sha256.c include/sha.h include/sha_common.h
	cc $(CFLAGS) -c src/sha256.c -o sha256.o

sha_common.o: src/sha_common.c include/sha_common.h
	cc $(CFLAGS) -c src/sha_common.c -o sha_common.o

clean:
	rm -f test *.o