#ifndef LINUX64_MIN_H
#define LINUX64_MIN_H

typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef short              int16_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef unsigned long      uint64_t;
typedef long               int64_t;
typedef unsigned long      size_t;
typedef long               ssize_t;

#define NULL ((void *)0)

/* Exact Linux x86_64 struct stat (144 bytes). */
struct linux_stat64 {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t  st_size;
    int64_t  st_blksize;
    int64_t  st_blocks;
    int64_t  st_atime;
    int64_t  st_atime_nsec;
    int64_t  st_mtime;
    int64_t  st_mtime_nsec;
    int64_t  st_ctime;
    int64_t  st_ctime_nsec;
    int64_t  __unused[3];
};

typedef char _check_stat_size[(sizeof(struct linux_stat64) == 144) ? 1 : -1];

/* Linux x86_64 pthread_mutex_t is 40 bytes. */
typedef struct { char opaque[40]; } linux_pthread_mutex_t;
typedef uint64_t linux_pthread_t;

extern int    printf(const char *fmt, ...);
extern int    snprintf(char *buf, size_t n, const char *fmt, ...);
extern int    puts(const char *s);
extern void  *malloc(size_t n);
extern void   free(void *p);
extern void  *memset(void *p, int c, size_t n);
extern void  *memcpy(void *d, const void *s, size_t n);
extern int    strcmp(const char *a, const char *b);
extern size_t strlen(const char *s);
extern void   qsort(void *base, size_t nmemb, size_t size, int (*cmp)(const void *, const void *));
extern int    stat(const char *path, struct linux_stat64 *st);
extern double sqrt(double x);

extern int pthread_create(linux_pthread_t *t, const void *attr, void *(*fn)(void *), void *arg);
extern int pthread_join(linux_pthread_t t, void **ret);
extern int pthread_mutex_init(linux_pthread_mutex_t *m, const void *attr);
extern int pthread_mutex_lock(linux_pthread_mutex_t *m);
extern int pthread_mutex_unlock(linux_pthread_mutex_t *m);
extern int pthread_mutex_destroy(linux_pthread_mutex_t *m);

#endif
