# Sleep proxy makefile
# Leigh Garbs

SRC := \
sproxy.cpp

INC := \
toolbox/logging/Log.hpp \
toolbox/networking/arp_ipv4.h \
toolbox/networking/ethernet_ii_header.h \
toolbox/networking/ipv4_header.h

LIB := \
toolbox/libtoolbox.a

sproxy: $(SRC) $(INC) $(LIB)
	g++ -I. -Itoolbox/networking -Itoolbox/logging -Wall -g2 -o $@ $(SRC) $(LIB)
