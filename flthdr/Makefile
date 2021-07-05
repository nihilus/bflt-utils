CC=gcc
CFLAGS=-Wall -g -O2 -I/usr/include/libiberty
LDFLAGS=-lz -lc -lbfd -liberty
TARGET=flthdr

$(TARGET): compress.o stubs.o flthdr.o
	$(CC) $(CFLAGS) -o $(TARGET) *.o $(LDFLAGS)

compress.o:
	$(CC) $(CFLAGS) compress.c -c

stubs.o:
	$(CC) $(CFLAGS) stubs.c -c

flthdr.o:
	$(CC) $(CFLAGS) flthdr.c -c

clean:
	rm -f *.o $(TARGET)
