SRC	= 	formula.cc

LDFLAGS =	-lmuparser
CFLAGS  += 	-Wall -fPIC -fpermissive
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

CCP		= g++
CC		= gcc

OBJ	= $(SRC:.cc=.o)

.SILENT:

all :   $(OBJ) TEST

TEST :
		$(CCP) $(CFLAGS) -c test.cc
		$(CCP) -o test test.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o $(LIBNAME).so

%.o   : %.cc
	echo " CC $@"
	$(CCP) $(CFLAGS) -c -o $@ $<
