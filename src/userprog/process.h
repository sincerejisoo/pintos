#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdbool.h>
#include "vm/page.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int parsing_argument(char *file_name, char **argv);
void process_init_stack(int argc, char **argv, void **esp);

bool fault_handler (struct page_entry *spte);
bool stack_grow (void *addr);

#endif /* userprog/process.h */
