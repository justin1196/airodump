LDLIBS=-lpcap

all: airodump

airodump: airodump.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f airodump *.o
  
