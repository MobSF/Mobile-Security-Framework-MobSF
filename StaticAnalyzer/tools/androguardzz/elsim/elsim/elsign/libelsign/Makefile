SRC	= 	elsign.cc

PATH_SIMILARITY = ../../similarity/libsimilarity/
PATH_FORMULA = ../formula/

CUROS = $(shell uname -s)

ifeq ($(CUROS),Darwin)
LDFLAGS =	-lm -lbz2 -lz -llzma -lsnappy -lmuparser -lpython
else
LDFLAGS =	-lm -lbz2 -lz -llzma -lsnappy -lmuparser
endif

CFLAGS  += 	-Wall -fPIC -I/usr/include/python2.7/ -I$(PATH_SIMILARITY) -I$(PATH_FORMULA)

mkdir	=	mkdir -p
CD      =       cd
RM      =       rm -f

EXT_SIMILARITY = $(PATH_SIMILARITY)similarity.o
EXT_FORMULA = $(PATH_FORMULA)formula.o
EXT_ZIP = $(PATH_SIMILARITY)z/z.o $(PATH_SIMILARITY)bz2/bz2.o $(PATH_SIMILARITY)smaz/smaz.o $(PATH_SIMILARITY)xz/xz.o $(PATH_SIMILARITY)snappy/snappy.o $(PATH_SIMILARITY)vcblocksort/vcblocksort.o
EXT_SDK_LZMA = $(PATH_SIMILARITY)lzma/Alloc.o  $(PATH_SIMILARITY)lzma/LzFind.o  $(PATH_SIMILARITY)lzma/LzmaDec.o  $(PATH_SIMILARITY)lzma/LzmaEnc.o  $(PATH_SIMILARITY)lzma/LzmaLib.o  $(PATH_SIMILARITY)lzma/lzma.o

CCP		= g++
CC		= gcc

LIBNAME = libelsign

OBJ	= $(SRC:.cc=.o)
AHO_OBJ = ac_heap.o ac_list.o aho_corasick.o
WUMANBER_OBJ = #WuManber.o 
CLUSTER_OBJ = cluster.o

.SILENT:

all :   AHO CLUSTER $(OBJ) LIBSIGN

AHO :
		$(CC) $(CFLAGS) -c ac_heap.c
		$(CC) $(CFLAGS) -c ac_list.c
		$(CC) $(CFLAGS) -c aho_corasick.c

CLUSTER :
		$(CC) $(CFLAGS) -c cluster.c

WUMANBER :
		$(CCP) $(CFLAGS) -c WuManber.cpp

LIBSIGN :
	$(CCP) -o $(LIBNAME).so $(OBJ) $(AHO_OBJ) $(WUMANBER_OBJ) $(CLUSTER_OBJ) $(EXT_SIMILARITY) $(EXT_FORMULA) $(EXT_ZIP) $(EXT_SDK_LZMA) -shared $(LDFLAGS)

clean :
	$(RM) *.o $(LIBNAME).so

%.o   : %.cc
	echo " CC $@"
	$(CCP) $(CFLAGS) -c -o $@ $<
