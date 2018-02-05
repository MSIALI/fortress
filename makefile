CC=gcc
LDFLAGS=$(shell pkg-config --libs libnl-genl-3.0)
DEBUG_FLAGS=-DDEBUG=1 -std=c99 -Wall -Wextra -Wpedantic -g 
FLAGS=-std=c99 -Wall -Wpedantic -Wno-unused-parameter
#DEBUG=0
ifeq (${DEBUG},1)
	FLAGS+=${DEBUG_FLAGS}
endif
#FLAGS+=${DEBUG_FLAGS}
FLAGS += $(shell pkg-config --cflags libnl-genl-3.0)

fortress: fortress.o
	${CC} -o $@ fortress.o ${LDFLAGS} ${FLAGS}

fortress.o: fortress.c
	${CC} -o $@ -c $< ${FLAGS}

clean:
	rm -rf *.o
