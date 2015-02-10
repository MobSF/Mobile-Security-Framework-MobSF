SRC	= 	snappy.cc

CC	=	gcc
CC2	=	g++
LDFLAGS =	-lsnappy
CFLAGS  +=      -Wall 
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.cc=.o)

#.SILENT:

all :  $(OBJ) test

test :
	$(CC) -c test_snappy.c $(CFLAGS) -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -fPIC
	$(CC2) -Bsymbolic-functions -o test_snappy test_snappy.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_snappy

%.o   : %.cc
	echo " CC $@"
	$(CC)  -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -fPIC $(CFLAGS) -c -o $@ $<
