FILES = pheap.c
OUT_BIN = pheap
CCFLAGS = -std=gnu99 -Wall -pedantic

build: $(FILES)
				$(CC) $(CCFLAGS) -O2 -o $(OUT_BIN) $(FILES)

clean:
				rm -f *.o pheap backing_file

rebuild: clean build

debug: $(FILES)
				$(CC) $(CCFLAGS) -g -o $(OUT_BIN) $(FILES)
