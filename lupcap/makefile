TARGET	=pcap_socket
SRCS	=$(wildcard *.cpp)
OBJECTS	=$(SRCS:.cpp=.o)

CPPFLAGS+=-I/Users/goka/android/sysroot/include
LDFLAGS+=-L/Users/goka/android/sysroot/lib
LDFLAGS+=-pie
LDLIBS+=-lpcap
#LDLIBS+=-pthread

$(TARGET) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(TARGET_ARCH) $(OBJECTS) $(LDLIBS) -o $(TARGET)


pcap_socket.o : pcap_socket.cpp
arp.o : arp.cpp
interface.o : interface.cpp


clean:
	rm -f $(TARGET)
	rm -f *.o

