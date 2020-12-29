all:
	gcc -g main.c $(shell pkg-config --cflags --libs r_core)
