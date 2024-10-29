CFLAGS = -O3 -Wall -I../
LDFLAGS = -lm

metric-provider-binary: source.c ../parse_int.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)