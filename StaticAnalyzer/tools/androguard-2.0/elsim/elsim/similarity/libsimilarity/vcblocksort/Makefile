SRC	= 	vcblocksort.c

LDFLAGS +=	-lm
CFLAGS  +=      -Wall -fPIC       
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)


all :  $(OBJ) test

test :
	$(CC) -c test_vcblocksort.c $(CFLAGS)
	$(CC) -o test_vcblocksort test_vcblocksort.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_vcblocksort

%.o   : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
