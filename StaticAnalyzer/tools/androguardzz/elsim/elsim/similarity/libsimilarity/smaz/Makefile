SRC	= 	smaz.c

LDFLAGS =
CFLAGS  +=      -Wall -fPIC      
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

OBJ	= $(SRC:.c=.o)

.SILENT:

all :  $(OBJ) test

test :
	$(CC) -c test_smaz.c $(CFLAGS)
	$(CC) -o test_smaz test_smaz.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o test_smaz

%.o   : %.c
	echo " CC $@"
	$(CC) $(CFLAGS) -c -o $@ $<
