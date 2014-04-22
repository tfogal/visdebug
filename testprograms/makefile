CFLAGS:=-std=c99 -Wall -Wextra -ggdb3
obj:=3dloop.o vardim.o
all: $(obj) 3dloop dimensional

3dloop: 3dloop.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

dimensional: vardim.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(obj) 3dloop dimensional
