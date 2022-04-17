#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>

#define MAX_LEN 300

//chmod chown close creat fclose fopen fread fwrite open read remove rename tmpfile write
int (*old_chmod)(const char *, mode_t);
int (*old_chown)(const char *, uid_t, gid_t);
int (*old_close)(int) = NULL;
int (*old_creat)(const char *, mode_t);
int (*old_fclose)(FILE *);
FILE *(*old_fopen)(const char *, const char *);
size_t (*old_fread)(void *, size_t, size_t, FILE *);
size_t (*old_fwrite)(const void *, size_t, size_t, FILE *);
int (*old_open)(const char *, int, ...);
ssize_t (*old_read)(int, void *, size_t);
int (*old_remove)(const char *);
int (*old_rename)(const char *, const char *);
FILE *(*old_tmpfile)(void);
ssize_t (*old_write)(int, const void *, size_t) = NULL;

int (*old_open64)(const char *, int, ...);

FILE *output_file = NULL;
int output_file_fd = -1;

void err_sys(const char* msg)
{
    perror(msg);
    exit(0);
}

void initial()
{
    void* handle = dlopen("libc.so.6", RTLD_LAZY);

    if(old_chmod == NULL)
        if(handle != NULL) 
            old_chmod = dlsym(handle, "chmod");

    if(old_chown == NULL)
        if(handle != NULL) 
            old_chown = dlsym(handle, "chown");

    if(old_close == NULL)
        if(handle != NULL) 
            old_close = dlsym(handle, "close");
    
    if(old_creat == NULL)
        if(handle != NULL) 
            old_creat = dlsym(handle, "creat");

    if(old_fclose == NULL)
        if(handle != NULL) 
            old_fclose = dlsym(handle, "fclose");

    if(old_fopen == NULL)
        if(handle != NULL) 
            old_fopen = dlsym(handle, "fopen");

    if(old_fread == NULL)
        if(handle != NULL) 
            old_fread = dlsym(handle, "fread");
    
    if(old_fwrite == NULL)
        if(handle != NULL) 
            old_fwrite = dlsym(handle, "fwrite");

    if(old_open == NULL)
        if(handle != NULL) 
            old_open = dlsym(handle, "open");
            
    if(old_read == NULL)
        if(handle != NULL) 
            old_read = dlsym(handle, "read");
    
    if(old_remove == NULL)
        if(handle != NULL) 
            old_remove = dlsym(handle, "remove");

    if(old_rename == NULL)
        if(handle != NULL) 
            old_rename= dlsym(handle, "rename");
            
    if(old_tmpfile == NULL)
        if(handle != NULL) 
            old_tmpfile = dlsym(handle, "tmpfile");

    if(old_write == NULL)
        if(handle != NULL) 
            old_write = dlsym(handle, "write");

    if(old_open64 == NULL)
        if(handle != NULL) 
            old_open64 = dlsym(handle, "open64");


    if(output_file_fd == -1)
    {
        char *output_file_char = getenv("FILE");
        if(strcmp(output_file_char, "stderr") == 0)
        {
            if((output_file_fd = dup(fileno(stderr))) < 0)
                err_sys("dup");
        }

        else if((output_file_fd = old_open(output_file_char, O_WRONLY|O_CREAT|O_APPEND, 0777)) < 0)
            err_sys("open");
            //!!! 本來用old_fopen 不知道why會一直沒有把資料append到file裡, 後來改用open就可以了
    }
}

char *find_fd_filename(int fd)
{
    pid_t pid = getpid();
    char path[MAX_LEN], fd_char[MAX_LEN];
    sprintf(path, "/proc/%d/fd", pid);
    sprintf(fd_char, "%d", fd);

    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir(path)) == NULL)
        err_sys("opendir");


    char *filename = NULL;
    if((filename = (char*)malloc(MAX_LEN)) == NULL)
        err_sys("malloc");
    memset(filename, 0, MAX_LEN);

    while((dirp = readdir(dp)) != NULL)
    {
        if(strcmp(dirp -> d_name, fd_char) == 0)
        {
            sprintf(path, "/proc/%d/fd/%d", pid, fd);
            if(readlink(path, filename, MAX_LEN) < 0)
                sprintf(filename, "(null)");

            break;
        }
    }
    return filename;
}

char *find_realpath(const char *pathname)
{
    char *resolved_path = NULL;
    if((resolved_path = malloc(MAX_LEN)) == NULL)
        err_sys("malloc");
    memset(resolved_path, 0, MAX_LEN);

    if(realpath(pathname, resolved_path) == NULL)
        strcpy(resolved_path, pathname);
    
    return resolved_path;
}

char *change_to_printable_buf(const char *ori_buf, int size)
{
    char *buf = NULL;
    if((buf = malloc(MAX_LEN)) == NULL)
        err_sys("malloc");
    memset(buf, 0, MAX_LEN);

    for(int i = 0; i < 32 && i < size; ++i)
    {
        if(isprint((int)ori_buf[i]) == 0)
            strcat(buf, ".");
        else
            strncat(buf, (ori_buf + i), 1);
    }

    return buf;
}


int chmod(const char *pathname, mode_t mode)
{
    initial();
    int return_val = old_chmod(pathname, mode);
    char *filename = find_realpath(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %o) = %d\n", "chmod", filename, mode, return_val);
    free(filename);

    return return_val;
}

int chown(const char *pathname, uid_t owner, gid_t group)
{
    initial();
    int return_val = old_chown(pathname, owner, group);
    char *filename = find_realpath(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %d, %d) = %d\n", "chown", filename, owner, group, return_val);
    free(filename);

    return return_val;
}

int close(int fd)
{
    initial();
    char *filename = find_fd_filename(fd);
    int return_val = old_close(fd);
    dprintf(output_file_fd, "[logger] %s(\"%s\") = %d\n", "close", filename, return_val);
    free(filename);

    return return_val;
}

int creat(const char *pathname, mode_t mode)
{
    initial();
    int return_val = old_creat(pathname, mode);
    char *filename = find_realpath(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %o) = %d\n", "creat", filename, mode, return_val);
    free(filename);

    return return_val;
}

int fclose(FILE *stream)
{
    initial();
    char *filename = find_fd_filename(fileno(stream));
    int return_val = old_fclose(stream);
    dprintf(output_file_fd, "[logger] %s(\"%s\") = %d\n", "fclose", filename, return_val);
    free(filename);

    return return_val;
}

FILE *fopen(const char *pathname, const char *mode)
{
    initial();
    FILE * return_val = old_fopen(pathname, mode);
    char *filename = find_realpath(pathname), *new_buf = change_to_printable_buf(mode, strlen(mode));
    dprintf(output_file_fd, "[logger] %s(\"%s\", \"%s\") = %p\n", "fopen", filename, new_buf, return_val);
    free(filename);
    free(new_buf);

    return return_val;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    initial();
    ssize_t return_val = old_fread(ptr, size, nmemb, stream);
    char *filename = find_fd_filename(fileno(stream)), *new_buf = change_to_printable_buf((char*)ptr, return_val);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %ld, %ld, \"%s\") = %ld\n", "fread", new_buf, size, nmemb, filename, return_val);
    free(filename);
    free(new_buf);
    
    return return_val;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    initial();
    ssize_t return_val = old_fwrite(ptr, size, nmemb, stream);
    char *filename = find_fd_filename(fileno(stream)), *new_buf = change_to_printable_buf((char*)ptr, size * nmemb);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %ld, %ld, \"%s\") = %ld\n", "fwrite", new_buf, size, nmemb, filename, return_val);
    free(filename);
    free(new_buf);
    
    return return_val;
}

int open(const char *pathname, int flags, ...)
{
    initial();

    int return_val = 0;
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE (flags))  // 來自glibc source code open的實作方式
    {
      va_list arg;
      va_start (arg, flags);
      mode = va_arg (arg, mode_t);
      va_end (arg);
      return_val = old_open(pathname, flags, mode);
    }

    else return_val = old_open(pathname, flags);
    
    char *filename = find_realpath(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %o, %o) = %d\n", "open", filename, flags, mode, return_val); // 000的情況不用處理, 助教說沒差
    free(filename);

    return return_val;
}

ssize_t read(int fd, void *buf, size_t count)
{
    initial();
    ssize_t return_val = old_read(fd, buf, count);
    char *filename = find_fd_filename(fd), *new_buf = change_to_printable_buf((char*)buf, return_val);
    dprintf(output_file_fd, "[logger] %s(\"%s\", \"%s\", %ld) = %ld\n", "read", filename, new_buf, count, return_val);
    free(filename);
    free(new_buf);
    
    return return_val;
}

int remove(const char *pathname)
{
    initial();
    char *filename = find_realpath(pathname);    
    int return_val = old_remove(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\") = %d\n", "remove", filename, return_val);
    free(filename);

    return return_val;
}

int rename(const char *oldpath, const char *newpath)
{
    initial();
    char *filename1 = find_realpath(oldpath), *filename2 = find_realpath(newpath);
    int return_val = old_rename(oldpath, newpath);
    dprintf(output_file_fd, "[logger] %s(\"%s\", \"%s\") = %d\n", "rename", filename1, filename2, return_val);
    free(filename1);
    free(filename2);

    return return_val;
}

FILE *tmpfile(void)
{
    initial();
    FILE * return_val = old_tmpfile();
    dprintf(output_file_fd, "[logger] %s() = %p\n", "tmpfile", return_val);

    return return_val;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    initial();
    ssize_t return_val = old_write(fd, buf, count);
    char *filename = find_fd_filename(fd), *new_buf = change_to_printable_buf((char*)buf, count);
    dprintf(output_file_fd, "[logger] %s(\"%s\", \"%s\", %ld) = %ld\n", "write", filename, new_buf, count, return_val);
    free(filename);
    free(new_buf);
    
    return return_val;
}


int open64(const char *pathname, int flags, ...)    //!!! 不知道需不需要支援大檔
{
    initial();

    int return_val = 0;
    mode_t mode = 0;
    if (__OPEN_NEEDS_MODE (flags))  // 來自glibc source code open的實作方式
    {
      va_list arg;
      va_start (arg, flags);
      mode = va_arg (arg, mode_t);
      va_end (arg);
      return_val = old_open64(pathname, flags, mode);
    }

    else return_val = old_open64(pathname, flags);
    
    char *filename = find_realpath(pathname);
    dprintf(output_file_fd, "[logger] %s(\"%s\", %o, %o) = %d\n", "open64", filename, flags, mode, return_val); // 000的情況不用處理, 助教說沒差
    free(filename);

    return return_val;
}