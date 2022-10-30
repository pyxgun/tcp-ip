PROG = a.out

ALL  = $(wildcard *.c) $(wildcard src/*.c)
OBJS = $(ALL:%.c=%.o)
INCS = ./include

COMPILER = gcc


all: $(PROG)

$(PROG): $(OBJS)
	$(COMPILER) -o $@ $(notdir $(OBJS))

%.o: %.c
	$(COMPILER) -c -O3 $(addprefix -I, $(INCS)) $<

clean:
	rm *.o