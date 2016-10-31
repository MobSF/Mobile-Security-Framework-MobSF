SRC	= 	bz2.c

LDFLAGS +=	-lbz2
CFLAGS  +=      -Wall -fPIC       
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)


all :  $(OBJ) test

test :
	$(CC) -c test_bz2.c $(CFLAGS)
	$(CC) -o test_bz2 test_bz2.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_bz2

%.o   : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
