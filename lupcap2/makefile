TARGET	=lupcapd
SRCS	=$(wildcard *.cpp)
OBJECTS	=$(SRCS:.cpp=.o)

CPPFLAGS+=-I/Users/goka/android/sysroot/include
LDFLAGS+=-L/Users/goka/android/sysroot/lib
LDFLAGS+=-pie
LDLIBS+=-lpcap

$(TARGET) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(TARGET_ARCH) $(OBJECTS) $(LDLIBS) -o $(TARGET)


lupcapd.o : lupcapd.cpp
main.o : main.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

