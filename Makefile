CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
TOOLS   = netscan.exe portscan.exe wifiscan.exe netwatch.exe

all: $(TOOLS)

netscan.exe: netscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ netscan.c -lws2_32 -liphlpapi

portscan.exe: portscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ portscan.c -lws2_32 -liphlpapi

wifiscan.exe: wifiscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ wifiscan.c -lws2_32 -lwlanapi -lole32

netwatch.exe: netwatch.c lantern.h
	$(CC) $(CFLAGS) -o $@ netwatch.c -lws2_32 -liphlpapi

clean:
	rm -f $(TOOLS)

.PHONY: all clean
