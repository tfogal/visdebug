F95=gfortran
CFLAGS:=-std=c99 -Wall -Wextra -ggdb3 -O3
FFLAGS:=-Wall -Wextra -ggdb3
obj:=3dloop.o vardim.o switch.o bcont.o nested.o loops.o waitfor.o
all: $(obj) 3dloop dimensional branching contbreak nest forloops pauser

3dloop: 3dloop.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

dimensional: vardim.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

branching: switch.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

contbreak: bcont.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

nest: nested.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

forloops: loops.o
	$(F95) $(FFLAGS) $^ -o $@ $(LDLIBS)

pauser: waitfor.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.f95
	$(F95) -c $(FFLAGS) $^ -o $@

clean:
	rm -f $(obj) 3dloop dimensional branching contbreak nest forloops nested
	rm -f pauser
