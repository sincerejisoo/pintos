#include "vm/frame.h"
#include "vm/swap.h"
#include <list.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include <string.h>
#include "filesys/file.h"

extern struct lock file_rw;

struct list frame_table;
struct lock ft_lock;
struct list_elem *frame_clock;

void ft_init() {
    list_init(&frame_table);
    lock_init(&ft_lock);

    frame_clock = NULL;
}

void frame_insert(struct frame *frame) {
    lock_acquire(&ft_lock);
    list_push_back(&frame_table, &frame->ft_elem);
    lock_release(&ft_lock);
}

void frame_delete(struct frame *frame) {
    lock_acquire(&ft_lock);
    if (frame_clock != &frame->ft_elem)	list_remove(&frame->ft_elem);
	else if (frame_clock == &frame->ft_elem) frame_clock = list_remove(frame_clock);
    lock_release(&ft_lock);
}

struct frame *frame_find(void *page_addr) {
    struct list_elem *e;
    struct frame *frame;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        frame = list_entry(e, struct frame, ft_elem);
        if (frame->physical_page == page_addr)
        {
            return frame;
        }
    }
    return NULL;
}

struct frame *alloc_frame(enum palloc_flags flags) {
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    if (!frame) return NULL;
    memset(frame, 0, sizeof(struct frame));
    frame->spte = NULL;
    frame->thread = thread_current();
    frame->physical_page = palloc_get_page(flags);
    while (frame->physical_page == NULL)
    {
        evict_frame();
        frame->physical_page = palloc_get_page(flags);
    }
    frame_insert(frame);
    return frame;
}

struct frame *find_frame_for_vaddr(void *vaddr) {
    struct list_elem *e;
    struct frame *frame;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        frame = list_entry(e, struct frame, ft_elem);
        if (pagedir_get_page(frame->thread->pagedir, vaddr) == frame->physical_page)
        {
            return frame;
        }
    }
    return NULL;
}

void free_frame(void *addr) {
    struct frame *frame = frame_find(addr);
    if (frame == NULL)
    {
        return;
    }
    frame->spte->is_loaded = false;
    pagedir_clear_page(frame->thread->pagedir, frame->spte->vaddr);
    palloc_free_page(frame->physical_page);
    frame_delete(frame);
    free(frame);
}

void evict_frame(void) {
    struct frame *frame_victim = NULL;
    while (true) {
        if (frame_clock == NULL || frame_clock==list_end(&frame_table)) frame_clock = list_begin(&frame_table);
        else frame_clock = list_next(frame_clock);
        if(frame_clock==list_end(&frame_table)) continue;
        frame_victim = list_entry(frame_clock, struct frame, ft_elem);
        if (frame_victim->pin) continue;
        if (!pagedir_is_accessed(frame_victim->thread->pagedir, frame_victim->spte->vaddr)) {
            break;
        }
        pagedir_set_accessed(frame_victim->thread->pagedir, frame_victim->spte->vaddr, false);
    }
    if (frame_victim == NULL)
    {
        PANIC("No victim found");
    }
    bool dirty_bit = pagedir_is_dirty(frame_victim->thread->pagedir, frame_victim->spte->vaddr);
    switch (frame_victim->spte->type){
        case SPTE_BIN:
            if (dirty_bit){
                frame_victim->spte->swap_slot = swap_out(frame_victim->physical_page);
                frame_victim->spte->type = SPTE_SWAP; 
            }
            break;
        case SPTE_FILE:
            if (dirty_bit){
                lock_acquire(&file_rw);
                file_write_at(frame_victim->spte->file, frame_victim->physical_page, PGSIZE, frame_victim->spte->offset);
                lock_release(&file_rw);
            }
            break;    
        case SPTE_SWAP:
            frame_victim->spte->swap_slot = swap_out(frame_victim->physical_page);
            break;
    }
    free_frame(frame_victim->physical_page);
}
void pin_user_frame(void *kaddr) {
    struct frame *frame = frame_find(kaddr);
    if (frame != NULL) {
        lock_acquire(&ft_lock);
        frame->pin = true;
        lock_release(&ft_lock);
    }    
}

void unpin_user_frame(void *kaddr) {
    struct frame *frame = frame_find(kaddr);
    if (frame != NULL) {
        lock_acquire(&ft_lock);
        frame->pin = false;
        lock_release(&ft_lock);
    }    
}