#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include "lib/user/syscall.h"

void syscall_init (void);

void get_argument(int *esp, int *args, int arg_count);

void sys_exit(int status);
pid_t sys_exec(const char *file, void *esp);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size, void *esp);
int sys_write(int fd, const void *buffer, unsigned size, void *esp);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);

mapid_t sys_mmap (int fd, void *addr);
void sys_munmap(mapid_t mapping);


#endif /* userprog/syscall.h */
