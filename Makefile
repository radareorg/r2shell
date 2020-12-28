all:
	gcc main.c $(shell pkg-config --cflags --libs r_core)
