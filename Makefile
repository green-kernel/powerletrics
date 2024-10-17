CFLAGS = -O3 -Wall
LDFLAGS = -lm

.PHONY: all clean

all: providers/parse_int.o providers/rapl/metric-provider-binary

providers/parse_int.o: providers/parse_int.c
	gcc -c $(CFLAGS) -o $@ $<

providers/rapl/metric-provider-binary: providers/rapl/source.c providers/parse_int.o
	gcc $(CFLAGS) -o $@ $^ -Iproviders/ $(LDFLAGS)

clean:
	rm -f providers/parse_int.o providers/rapl/metric-provider-binary
