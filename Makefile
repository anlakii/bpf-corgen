CC=clang
CFLAGS=-g -DERROR -DDEBUG -DLOG -DWARNING -Wall -lbpf -ljson-c -lcap

gen: src/*
	$(CC) $(CFLAGS) src/main.c src/gen.c src/helpers.c src/loader.c src/config.c src/insn_handlers.c -o corgen

clean:
	find . -type f -iname "*.c" -exec clang-format -style=file -i {} \;
	find . -type f -iname "*.h" -exec clang-format -style=file -i {} \;
	rm corgen
