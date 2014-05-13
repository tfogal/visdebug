PARSE:=$(HOME)/sw
CXXFLAGS:=-std=c++11 -Wall -Wextra -I$(PARSE)/include -ggdb3 -DMAIN
LDLIBS:=-L$(PARSE)/lib -lparseAPI -lsymLite
obj:=cfg.o

all: $(obj) printcfg

printcfg: cfg.o
	$(CXX) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(obj) printcfg
