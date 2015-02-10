SRC	= 	dvm.cc buff.cc

CUROS = $(shell uname -s)
ifeq ($(CUROS),Darwin)
LDFLAGS =       -lpython
else
LDFLAGS =
endif

CFLAGS  += 	-g -fPIC -I/usr/include/python2.7/       
mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

CCP		= g++

LIBNAME = dvmnative

OBJ	= $(SRC:.cc=.o)

.SILENT:

all :   $(OBJ) LIBDVM

LIBDVM :
	$(CCP) -o $(LIBNAME).so $(OBJ) -shared $(LDFLAGS)

clean :
	$(RM) *.o $(LIBNAME).so

%.o   : %.cc
	echo " CCP $@"
	$(CCP) $(CFLAGS) -c -o $@ $<
