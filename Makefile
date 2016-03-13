all:
	gcc -Wall src/dfs_fuse.c `pkg-config fuse --cflags --libs` -o bin/difuse

clean:
	rm bin/difuse
