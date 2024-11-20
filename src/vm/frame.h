#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

struct frame
{
	void *physical_page;
	struct page_entry *spte;
	struct thread *thread;
	struct list_elem ft_elem; 
};

extern struct list frame_table;
extern struct lock ft_lock;
extern struct list_elem *frame_clock;

void ft_init();
void frame_insert(struct frame *frame);
void frame_delete(struct frame *frame);
struct frame *frame_find(void *page_addr);
struct frame *alloc_frame(enum palloc_flags flags);

struct frame *find_frame_for_vaddr(void* vaddr);
void free_frame(void *addr);

void evict_frame(void);

#endif