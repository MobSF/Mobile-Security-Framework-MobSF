SRC	= 	Alloc.c LzFind.c LzmaDec.c LzmaEnc.c LzmaLib.c lzma.c

LDFLAGS =
CFLAGS  =      -Wall -D_7ZIP_ST -fPIC  
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)

.SILENT:

all :  $(OBJ) test

test :
	$(CC) -c test_lzma.c $(CFLAGS)
	$(CC) -o test_lzma test_lzma.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_lzma

%.o   : %.c
	echo " CC $@"
	$(CC) $(CFLAGS) -c -o $@ $<
