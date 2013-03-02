# Sleep proxy makefile
# Leigh Garbs

TARGET := sproxy

SOURCE := \
logging.cpp

INCLUDE := \
netstructs/arp_ipv4.h \
netstructs/ethernet_ii_header.h \
netstructs/ipv4_header.h \
logging.hpp \
sproxy.hpp

$(TARGET): $(TARGET).cpp $(SOURCE) $(INCLUDE)
	g++ -I. -Inetstructs -Isocket -Lsocket -Wall -g2 -o $@ $< $(SOURCE) socket/libsocket.a
