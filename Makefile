PROG = a.out

ALL  = $(wildcard *.c) $(wildcard src/*.c)
OBJS = $(ALL:%.c=%.o)
INCS = ./include

COMPILER = gcc


all: $(PROG)

$(PROG): $(OBJS)
	$(COMPILER) -fsanitize=address -fno-omit-frame-pointer -o $@ $(notdir $(OBJS))

%.o: %.c
	$(COMPILER) -c -O2 $(addprefix -I, $(INCS)) $<

clean:
	rm *.o