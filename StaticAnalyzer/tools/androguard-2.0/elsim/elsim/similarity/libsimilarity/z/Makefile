SRC	= 	z.c

LDFLAGS +=	-lz
CFLAGS  +=      -Wall -fPIC      
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)


all :  $(OBJ) test

test :
	$(CC) -c test_z.c $(CFLAGS)
	$(CC) -o test_z test_z.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_z

%.o   : %.c
	$(CC) $(CFLAGS) -c -o $@ $<
