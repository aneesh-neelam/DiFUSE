/*
 *  Dissident File System (DFS)
 *  Copyright (C) 2016  Aneesh Neelam <neelam.aneesh@gmail.com & aneelam@ucsc.edu>
 *
 *  This file is part of the Dissident File System (DFS).
 *
 *  DFS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  DFS is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with DFS.  If not, see <http://www.gnu.org/licenses/>.
 */


#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif


// Helper functions and data structures for Dissident File System

#define DUMMY_FILES 2 // N value

char dfs_key[DUMMY_FILES + 1];

int dfs_random_number_generator() {
  int r;

  r = rand() % DUMMY_FILES;

  return r;
}

int dfs_get_paths(char **paths, const char *path) {
  int path_length;
  int dummy_index;

  path_length = strlen(path);
  paths[0] = (char*) malloc(path_length + 1);
  strncpy(paths[0], path, path_length);

  for (dummy_index = 1; dummy_index < DUMMY_FILES; ++dummy_index) {
    paths[dummy_index] = (char*) malloc(path_length + DUMMY_FILES + 1);
    strncpy(paths[dummy_index], path, path_length);
    strncat(path[dummy_index], dfs_key, DUMMY_FILES);
  }

  return 0;
}

int dfs_xor_combine(char **srcs, size_t size) {
  int dummy_index;
  int ptr_index;

  for (dummy_index = 1; dummy_index < DUMMY_FILES; ++dummy_index) {
    for (ptr_index = 0; ptr_index < size; ++ptr_index) {
       srcs[0][ptr_index] ^= srcs[dummy_index][ptr_index];
    }
  }

  return 0;
}

int dfs_xor_split(char **dest, const char *src, size_t size) {
  int dummy_index;
  int ptr_index;
  int true_index;
  int value;

  true_index = dfs_random_number_generator();
  memcpy(dest[true_index], src, size);

  value = 0;
  for (dummy_index = 0; dummy_index < DUMMY_FILES; ++dummy_index) {
    if (dummy_index != true_index) {
      for (ptr_index = 0; ptr_index < size; ++ptr_index) {
         dest[dummy_index] = src[ptr_index] ^ src[ptr_index];
      }
    }
  }

  return 0;
}

void dfs_usage() {
  fprintf(stderr, "Usage: difuse [mount_point] [dfs_key of %d digits]\n", DUMMY_FILES);
}


// FUSE operations functions

static int dfs_getattr(const char *path, struct stat *stbuf) {
 	int res;

 	res = lstat(path, stbuf);
 	if (res == -1)
 		return -errno;

 	return 0;
}

static int dfs_access(const char *path, int mask) {
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_readlink(const char *path, char *buf, size_t size) {
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int dfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int dfs_mknod(const char *path, mode_t mode, dev_t rdev) {
	int res;

	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev); // For Linux systems, this is sufficient
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_mkdir(const char *path, mode_t mode) {
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_unlink(const char *path) {
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_rmdir(const char *path) {
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_symlink(const char *from, const char *to) {
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_rename(const char *from, const char *to) {
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_link(const char *from, const char *to) {
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_chmod(const char *path, mode_t mode) {
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_chown(const char *path, uid_t uid, gid_t gid) {
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_truncate(const char *path, off_t size) {
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int dfs_utimens(const char *path, const struct timespec ts[2]) {
	int res;

	// Apparently, utime/utimes follow symlinks.
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int dfs_open(const char *path, struct fuse_file_info *fi) {
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int dfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	int fds[DUMMY_FILES];
	int results[DUMMY_FILES];
  int dummy_index;
  char *dummies[DUMMY_FILES] = {NULL};
  char *paths[DUMMY_FILES] = {NULL};

  (void) fi;

  dfs_get_paths(paths, path);
  for (dummy_index = 0; dummy_index < DUMMY_FILES; ++dummy_index) {
    fds[dummy_index] = open(paths[dummy_index], O_RDONLY);
    if (fds[dummy_index] == -1) {
  		return -errno;
    }

    dummies[dummy_index] = (char*) malloc(size);

    results[dummy_index] = pread(fds[dummy_index], dummies[dummy_index], size, offset);
  }

  dfs_xor_combine(dummies, size);
  memcpy(buf, dummies[0], size);

  for (dummy_index = 0; dummy_index < DUMMY_FILES; ++dummy_index) {
    close(fds[dummy_index]);
    free(dummies[dummy_index]);
    if (results[dummy_index] == -1) {
  		results[dummy_index] = -errno;
    }
  }

	return results[0];
}

static int dfs_write(const char *path, const char *buf, size_t size,off_t offset, struct fuse_file_info *fi) {
  int fds[DUMMY_FILES];
	int results[DUMMY_FILES];
  int dummy_index;
  char *dummies[DUMMY_FILES] = {NULL};
  char *paths[DUMMY_FILES] = {NULL};

	(void) fi;

  for (dummy_index = 0; dummy_index < DUMMY_FILES; ++dummy_index) {
    dummies[dummy_index] = (char*) malloc(size);
  }

  dfs_xor_split(dummies, buf, size);
  dfs_get_paths(paths, path);
  for (dummy_index = 0; dummy_index < DUMMY_FILES; ++dummy_index) {
    fds[dummy_index] = open(paths[dummy_index], O_WRONLY);
    if (fds[dummy_index] == -1) {
  		return -errno;
    }

    results[dummy_index] = pwrite(fds[dummy_index], dummies[dummy_index], size, offset);
    if (results[dummy_index] == -1) {
  		return -errno;
    }

    close(fds[dummy_index]);
  }

	return results[0];
}

static int dfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int dfs_release(const char *path, struct fuse_file_info *fi) {
	// Just a stub.	 This method is optional and can safely be left unimplemented.

	(void) path;
	(void) fi;
	return 0;
}

static int dfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	// Just a stub.	 This method is optional and can safely be left unimplemented.

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int dfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi) {
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int dfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int dfs_getxattr(const char *path, const char *name, char *value, size_t size) {
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int dfs_listxattr(const char *path, char *list, size_t size) {
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int dfs_removexattr(const char *path, const char *name) {
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations dfs_oper = {
	.getattr	= dfs_getattr,
	.access		= dfs_access,
	.readlink	= dfs_readlink,
	.readdir	= dfs_readdir,
	.mknod		= dfs_mknod,
	.mkdir		= dfs_mkdir,
	.symlink	= dfs_symlink,
	.unlink		= dfs_unlink,
	.rmdir		= dfs_rmdir,
	.rename		= dfs_rename,
	.link		= dfs_link,
	.chmod		= dfs_chmod,
	.chown		= dfs_chown,
	.truncate	= dfs_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= dfs_utimens,
#endif
	.open		= dfs_open,
	.read		= dfs_read,
	.write		= dfs_write,
	.statfs		= dfs_statfs,
	.release	= dfs_release,
	.fsync		= dfs_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= dfs_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= dfs_setxattr,
	.getxattr	= dfs_getxattr,
	.listxattr	= dfs_listxattr,
	.removexattr	= dfs_removexattr,
#endif
};

int main(int argc, char *argv[]) {
  umask(0);

  if (argc < 3) {
    dfs_usage();
    exit(1);
  }
  else if (strlen(argv[2]) != DUMMY_FILES) {
    dfs_usage();
    exit(1);
  }
  else {
    strncpy(dfs_key, argv[2], DUMMY_FILES);
    fprintf(stdout, "Using key: %s\n", dfs_key);
    argc = argc - 1;

	  return fuse_main(argc, argv, &dfs_oper, NULL);
  }
}
