# Sleep proxy makefile
# Leigh Garbs

SRC := \
sproxy.cpp

INC := \
log/Log.hpp \
netstructs/arp_ipv4.h \
netstructs/ethernet_ii_header.h \
netstructs/ipv4_header.h \
sproxy.hpp

LIB := \
log/liblog.a \
socket/libsocket.a

sproxy: $(SRC) $(INC) $(LIB)
	g++ -I. -Ilog -Inetstructs -Isocket -Wall -g2 -o $@ $(SRC) $(LIB)
