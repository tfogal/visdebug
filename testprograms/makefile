F95=gfortran
CXXFLAGS:=-std=c++11 -Wall -Wextra -gdwarf-3 -fPIC
CFLAGS:=-std=gnu99 -Wall -Wextra -gdwarf-3 -fPIC -fno-omit-frame-pointer
FFLAGS:=-Wall -Wextra -gdwarf-3 -fPIC
obj:=3dloop.o vardim.o switch.o bcont.o nested.o loops.o waitfor.o \
  tiny.o use.o smooth3d.o stack.o indirect.o
all: $(obj) 3dloop dimensional branching contbreak nest forloops pauser s3d \
  checkstack indirect

3dloop: 3dloop.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

dimensional: vardim.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

branching: switch.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

checkstack : stack.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

contbreak: bcont.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

nest: nested.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

forloops: loops.o
	$(F95) $(FFLAGS) $^ -o $@ $(LDLIBS)

pauser: waitfor.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

s3d: smooth3d.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

small: use.o libtiny.so
	$(CC) $(CFLAGS) $< -o $@ -L. -ltiny $(LDLIBS)

libtiny.so: tiny.o
	$(CC) $(CFLAGS) -shared -fPIC $^ -o $@

indirect: indirect.o
	$(CXX) $(CXXFLAGS) -fPIC $^ -o $@

%.o: %.f95
	$(F95) -c $(FFLAGS) $^ -o $@

clean:
	rm -f $(obj) 3dloop dimensional branching contbreak nest forloops nested
	rm -f pauser small checkstack s3d indirect
