CD      =       cd
RM      =       rm -f


.SILENT:

all :   LIBS

LIBS :
	cd formula && make
	cd libelsign && make

clean :
	cd formula && make clean
	cd libelsign && make clean
