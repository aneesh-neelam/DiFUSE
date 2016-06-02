all:
	gcc -Wall -ldb_cxx -lcrypto src/dfs_fuse.c `pkg-config fuse --cflags --libs` -o bin/difuse

clean:
	rm bin/difuse
