# Sleep proxy makefile
# Leigh Garbs

SRC := \
sproxy.cpp

INC := \
toolbox/misc/Log.hpp \
toolbox/networking/arp_ipv4.h \
toolbox/networking/ethernet_ii_header.h \
toolbox/networking/ipv4_header.h

LIB := \
toolbox/libtoolbox.a

sproxy: $(SRC) $(INC) $(LIB)
	@g++ -I. -Itoolbox/networking -Itoolbox/misc -Wall -g2 -o $@ $(SRC) $(LIB)

clean:
	@rm -rf sproxy
