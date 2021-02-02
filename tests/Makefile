CC	:= gcc
CFLAGS	:= -g -Wall -pthread
LIBS	:= -lpthread

all:  test01

test01:  test01.c
	$(CC) -g -Wall -pthread -o test01 test01.c $(LIBS)

clean:
	@rm -f *.o *~ test01
