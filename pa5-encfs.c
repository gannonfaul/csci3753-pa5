/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define ENC_XATTR "user.enc"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

typedef struct {
	char *key;
	char *rootdir;

} enc_state;



static void enc_fullpath(char fpath[PATH_MAX], const char *path)
{
	enc_state *data = (enc_state *) (fuse_get_context()->private_data);
	strcpy(fpath, data->rootdir);
	strncat(fpath, path, PATH_MAX);
}


static int enc_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);


	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int enc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
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

static int enc_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int enc_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int enc_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	(void) fi;
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int enc_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int enc_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
    char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int enc_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int enc_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int enc_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	int res = lsetxattr(fpath, name, value, size, flags);

	if (res == -1)
		return -errno;
	return 0;
}

static int enc_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int enc_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int enc_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	enc_fullpath(fpath, path);

	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations enc_oper = {
	.getattr	= enc_getattr,
	.access		= enc_access,
	.readlink	= enc_readlink,
	.readdir	= enc_readdir,
	.mknod		= enc_mknod,
	.mkdir		= enc_mkdir,
	.symlink	= enc_symlink,
	.unlink		= enc_unlink,
	.rmdir		= enc_rmdir,
	.rename		= enc_rename,
	.link		= enc_link,
	.chmod		= enc_chmod,
	.chown		= enc_chown,
	.truncate	= enc_truncate,
	.utimens	= enc_utimens,
	.open		= enc_open,
	.read		= enc_read,
	.write		= enc_write,
	.statfs		= enc_statfs,
	.create         = enc_create,
	.release	= enc_release,
	.fsync		= enc_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= enc_setxattr,
	.getxattr	= enc_getxattr,
	.listxattr	= enc_listxattr,
	.removexattr	= enc_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

	// argc = 4
	// argv = [./pa5-encfs, <Key>, <Directory>, <Mount Point>]

	enc_state *enc_data;
	enc_data = malloc(sizeof(enc_state));

	enc_data->key = argv[1];
	enc_data->rootdir = realpath(argv[2], NULL);

	argc -= 2;
	argv += 2;

	return fuse_main(argc, argv, &enc_oper, enc_data);
}
