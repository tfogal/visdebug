PARSE:=$(HOME)/sw
CFLAGS:=-std=c99 -Wall -Wextra -Werror -ggdb3 -DMAIN -Wno-unused-function
LDLIBS:=-lbfd -lelf
obj:=procbfd.o wrapbfd.o syms.o

all: $(obj) dyn attach

dyn: procbfd.o wrapbfd.o
	$(CC) $^ -o $@ $(LDLIBS)
attach: syms.o wrapbfd.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(obj) dyn attach
