# Sleep proxy makefile
# Leigh Garbs

TARGET := sproxy

SOURCE := \
logging.cpp

INCLUDE := \
net_structs/arp_ipv4.h \
net_structs/ethernet_ii_header.h \
net_structs/ipv4_header.h \
logging.hpp \
sproxy.hpp

$(TARGET): $(TARGET).cpp $(SOURCE) $(INCLUDE)
	g++ -I. -Inet_structs -Isocket -Lsocket -Wall -g2 -o $@ $< $(SOURCE) socket/libsocket.a
