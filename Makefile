CC      = gcc
FLAGS   = -Wall -lcrypto -ggdb -std=c99
CFS     = $(wildcard *.c)
OBJECTS = $(addsuffix .o, $(basename $(CF) ) )
PROG    = ccm

all:
	$(CC) -o $(PROG) $(CFS) $(FLAGS)

debug:
	$(CC) -o $(PROG) $(CFS) $(FLAGS) -DDEBUG

clean:
	@rm -f $(OBJECTS) $(PROG)
