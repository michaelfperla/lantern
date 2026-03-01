CC      = gcc
CFLAGS  = -O2 -Wall -Wextra
TOOLS   = netscan.exe portscan.exe wifiscan.exe netwatch.exe routercheck.exe netreport.exe
ATTACK  = keygen.exe wificrack.exe

all: $(TOOLS)

attack: $(ATTACK)

netscan.exe: netscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ netscan.c -lws2_32 -liphlpapi

portscan.exe: portscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ portscan.c -lws2_32 -liphlpapi

wifiscan.exe: wifiscan.c lantern.h
	$(CC) $(CFLAGS) -o $@ wifiscan.c -lws2_32 -lwlanapi -lole32

netwatch.exe: netwatch.c lantern.h
	$(CC) $(CFLAGS) -o $@ netwatch.c -lws2_32 -liphlpapi

routercheck.exe: routercheck.c lantern.h
	$(CC) $(CFLAGS) -o $@ routercheck.c -lws2_32 -liphlpapi

netreport.exe: netreport.c lantern.h
	$(CC) $(CFLAGS) -o $@ netreport.c -lws2_32 -liphlpapi -lwlanapi -lole32

keygen.exe: keygen.c lantern.h
	$(CC) $(CFLAGS) -o $@ keygen.c -lws2_32 -liphlpapi -lwlanapi -lole32

wificrack.exe: wificrack.c lantern.h
	$(CC) $(CFLAGS) -o $@ wificrack.c -lws2_32 -liphlpapi -lwlanapi -lole32

clean:
	rm -f $(TOOLS) $(ATTACK)

.PHONY: all attack clean
