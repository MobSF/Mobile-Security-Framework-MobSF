SRC	= 	formula.cc

LDFLAGS +=	-lmuparser
CFLAGS  += 	-Wall -fPIC -fpermissive
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

CXX		?= g++
CC		?= gcc

OBJ	= $(SRC:.cc=.o)


all :   $(OBJ) TEST

TEST :
		$(CXX) $(CFLAGS) -c test.cc
		$(CXX) -o test test.o $(OBJ) $(LDFLAGS)

clean :
	$(RM) *.o $(LIBNAME).so

%.o   : %.cc
	$(CXX) $(CFLAGS) -c -o $@ $<
