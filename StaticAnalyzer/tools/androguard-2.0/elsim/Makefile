CD      =       cd
RM      =       rm -f


all :   LIBS

LIBS :
	cd elsim/similarity && make
	cd elsim/elsign && make 

clean :
	cd elsim/similarity && make clean
	cd elsim/elsign && make clean
