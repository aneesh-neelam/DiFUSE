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
#include <db.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define PATH_MAX 256

// Helper functions and data structures for the Dissident File System

// File system state
struct dfs_state {
    char *passphrase;
    char *root_directory;
    char *mount_point;
    char *db_file;
    char *innocent_file;
};

DB *dbp; // BerkeleyDB structure handle

// Easy way to access file system state
#define DFS_DATA ((struct dfs_state *) fuse_get_context()->private_data)

// Random number store
typedef struct RANDOM {
    int last;
    char *data;
} RANDOM;
RANDOM csprn = {.last = 600};

// Generates random numbers
off_t generate_csprn() {
    if (csprn.last > 512) {
        if (csprn.data == NULL) {
            csprn.data = (char *) malloc(512);
        }

        int random_file = open("/dev/random", O_RDONLY);
        read(random_file, csprn.data, 512);
        close(random_file);

        csprn.last = 0;
    }
    else {
        csprn.last++;
    }

    if (csprn.data[csprn.last] < 0) {
      csprn.data[csprn.last] *= -1;
    }
    return csprn.data[csprn.last];
}

int dfs_xor(const char *src1, const char *src2, char *dest, size_t size) {
    size_t i;

    for (i = 0; i < size; ++i) {
        dest[i] = src1[i] ^ src2[i];
    }

    return 0;
}

int init_db(const char *native_db_file) {
    u_int32_t flags;
    int dbstatus;

    flags = DB_CREATE;
    dbstatus = dbp->open(dbp,
                         NULL,
                         native_db_file,
                         NULL,
                         DB_BTREE,
                         flags,
                         0);

    if (dbp != NULL) {
        dbp->close(dbp, 0);
    }

    return dbstatus;
}

off_t get_offset(const char * path) {
    off_t offset = -1;
    u_int32_t flags;
    int dbstatus;
    DBT key, data;

    flags = DB_RDONLY;
    dbstatus = dbp->open(dbp,
                         NULL,
                         DFS_DATA->db_file,
                         NULL,
                         DB_BTREE,
                         flags,
                         0);
    if (dbstatus != 0) {
        perror("dfs_getoffset: DB open failed\n");
        if (dbp != NULL) {
            dbp->close(dbp, 0);
        }
        return -1;
    }

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    key.data = path;
    key.size = sizeof(path) + 1;
    data.data = &offset;
    data.ulen = sizeof(off_t);
    data.flags = DB_DBT_USERMEM;

    dbstatus = dbp->get(dbp, NULL, &key, &data, 0);
    if (dbstatus != 0) {
        perror("dfs_getoffset: DB get failed\n");
        if (dbp != NULL) {
            dbp->close(dbp, 0);
        }
        return -1;
    }

    if (dbp != NULL) {
        dbp->close(dbp, 0);
    }

    return offset;
}

off_t set_offset(const char * path) {
    off_t offset = -1;
    u_int32_t flags;
    int dbstatus;
    DBT key, data;

    flags = DB_CREATE;
    dbstatus = dbp->open(dbp,
                         NULL,
                         DFS_DATA->db_file,
                         NULL,
                         DB_BTREE,
                         flags,
                         0);

    if (dbstatus != 0) {
        perror("dfs_getoffset: DB open failed\n");
        return -1;
    }

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    key.data = path;
    key.size = sizeof(path) + 1;
    data.data = &offset;
    data.ulen = sizeof(off_t);
    data.flags = DB_DBT_USERMEM;

    dbstatus = dbp->get(dbp, NULL, &key, &data, 0);

    if (dbstatus == 0) {
        perror("dfs_getoffset: DB get failed\n");
        offset = -1;
    }
    else if (dbstatus == DB_NOTFOUND) {
        offset = generate_csprn();

        memset(&data, 0, sizeof(DBT));
        data.data = &offset;
        data.size = sizeof(off_t);

        dbstatus = dbp->put(dbp, NULL, &key, &data, 0);
        if (dbstatus != 0) {
            perror("dfs_getoffset: DB put failed\n");
            offset = -1;
        }
    }

    if (dbp != NULL) {
        dbp->close(dbp, 0);
    }

    return offset;
}

off_t get_dboffset(char *passphrase) {
    size_t length = sizeof(passphrase);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(passphrase, length, hash);
    return hash[0];
}

void dfs_usage() {
    fprintf(stderr, "Usage: difuse [passphrase] [root_directory] [mount_point] [db_filename] [innocent_filepath\n\n");
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
    int fd, innocentfd;
    int res, innocentres, dbres;
    off_t innocentoffset;
    char *sensitivebuf;
    char *innocentbuf;
    struct stat pathstat;
    struct stat dbstat;

    (void) fi;

    /*
    res = stat(path, &pathstat);
    dbres = stat(DFS_DATA->db_file, &dbstat);
    if (res == -1 || dbres == -1)
        return -errno;

    if (pathstat.st_ino == dbstat.st_ino) {
      innocentoffset = get_dboffset(DFS_DATA->passphrase);
    }
    else {
      innocentoffset = get_offset(path);
    }
    */
    
    innocentoffset = get_dboffset(DFS_DATA->passphrase);

    fd = open(path, O_RDONLY);
    innocentfd = open(DFS_DATA->innocent_file, O_RDONLY);
    if (fd == -1 || innocentfd == -1)
        return -errno;

    sensitivebuf = (char *) malloc(size);
    innocentbuf = (char *) malloc(size);

    innocentres = pread(innocentfd, innocentbuf, size, innocentoffset + offset);
    res = pread(fd, sensitivebuf, size, offset);
    if (res == -1 || innocentres == -1)
        res = -errno;

    dfs_xor(sensitivebuf, innocentbuf, buf, size);

    free(sensitivebuf);
    free(innocentbuf);
    close(fd);
    close(innocentfd);

    return res;
}

static int dfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int fd, innocentfd;
    int res, innocentres, dbres;
    off_t innocentoffset;
    char *resultantbuf;
    char *innocentbuf;
    struct stat pathstat;
    struct stat dbstat;

    (void) fi;

    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -errno;

    /*
    res = stat(path, &pathstat);
    dbres = stat(DFS_DATA->db_file, &dbstat);
    if (res == -1 || dbres == -1)
        return -errno;

    if (pathstat.st_ino == dbstat.st_ino) {
        innocentoffset = get_dboffset(DFS_DATA->passphrase);
    }
    else {
        innocentoffset = get_offset(pathstat.st_ino);
    }
    */

    innocentoffset = get_dboffset(DFS_DATA->passphrase);

    innocentfd = open(DFS_DATA->innocent_file, O_RDONLY);
    if (innocentfd == -1)
        return -errno;

    resultantbuf = (char *) malloc(size);
    innocentbuf = (char *) malloc(size);

    innocentres = pread(innocentfd, innocentbuf, size, innocentoffset + offset);
    if (innocentres == -1)
        return -errno;

    dfs_xor(buf, innocentbuf, resultantbuf, size);

    res = pwrite(fd, resultantbuf, size, offset);
    if (res == -1)
        res = -errno;

    free(resultantbuf);
    free(innocentbuf);
    close(fd);
    close(innocentfd);

    return res;
}

static int dfs_statfs(const char *path, struct statvfs *stbuf) {
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
        .getattr    = dfs_getattr,
        .access        = dfs_access,
        .readlink    = dfs_readlink,
        .readdir    = dfs_readdir,
        .mknod        = dfs_mknod,
        .mkdir        = dfs_mkdir,
        .symlink    = dfs_symlink,
        .unlink        = dfs_unlink,
        .rmdir        = dfs_rmdir,
        .rename        = dfs_rename,
        .link        = dfs_link,
        .chmod        = dfs_chmod,
        .chown        = dfs_chown,
        .truncate    = dfs_truncate,
#ifdef HAVE_UTIMENSAT
        .utimens	= dfs_utimens,
#endif
        .open        = dfs_open,
        .read        = dfs_read,
        .write        = dfs_write,
        .statfs        = dfs_statfs,
        .release    = dfs_release,
        .fsync        = dfs_fsync,
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
    struct dfs_state *dfs_data;
    int dbstatus;

    printf("FUSE library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    if ((argc < 6) || (argv[argc - 5][0] == '-') || (argv[argc - 4][0] == '-') || (argv[argc - 3][0] == '-') ||
        (argv[argc - 2][0] == '-')) {
        dfs_usage();
        abort();
    }

    // Initializing File system state
    dfs_data = malloc(sizeof(struct dfs_state));
    if (dfs_data == NULL) {
        perror("dfs_main: DFS_State allocation failed\n");
        abort();
    }
    dfs_data->passphrase = argv[argc - 5];
    dfs_data->root_directory = realpath(argv[argc - 4], NULL);
    dfs_data->mount_point = realpath(argv[argc - 3], NULL);
    // dfs_data->db_file = realpath(argv[argc - 2], NULL);
    dfs_data->db_file = malloc(PATH_MAX);
    strncpy(dfs_data->db_file, dfs_data->mount_point, PATH_MAX);
    strncat(dfs_data->db_file, argv[argc - 2], PATH_MAX);
    dfs_data->innocent_file = realpath(argv[argc - 1], NULL);

    printf("Passphrase: %s\nRoot Directory: %s\nMount Point: %s\nDFS DB File: %s\nDFS Innocent File: %s\n",
           dfs_data->passphrase, dfs_data->root_directory, dfs_data->mount_point, dfs_data->db_file,
           dfs_data->innocent_file);


    dbstatus = db_create(&dbp, NULL, 0);
    if (dbstatus != 0) {
        perror("dfs_main: DB structure init failed\n");
        abort();
    }
    dbstatus = init_db(realpath(argv[argc - 2], NULL));
    if (dbstatus != 0) {
        perror("dfs_main: DB file init failed\n");
        abort();
    }

    // FUSE arguements
    argv[argc - 5] = argv[argc - 3];
    argv[argc - 4] = NULL;
    argv[argc - 3] = NULL;
    argv[argc - 2] = NULL;
    argv[argc - 1] = NULL;
    argc = argc - 4;

    return fuse_main(argc, argv, &dfs_oper, dfs_data);
}
