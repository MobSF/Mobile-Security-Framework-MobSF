SRC	= 	xz.c

LDFLAGS +=	-llzma
CFLAGS  +=      -Wall -fPIC       
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)


all :  $(OBJ) test

test :
	$(CC) -c test_xz.c $(CFLAGS)
	$(CC) -o test_xz test_xz.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_xz

%.o   : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
