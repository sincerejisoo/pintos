#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/file.h"


static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED);
static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
extern struct lock file_rw;

void SPT_init(struct hash *SPT) {
    hash_init(SPT, spt_hash_func, spt_less_func, NULL);
}

static unsigned spt_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct page_entry *spte = hash_entry(e, struct page_entry, elem);
    return hash_bytes(&spte->vaddr, sizeof(spte->vaddr));
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct page_entry *spte_a = hash_entry(a, struct page_entry, elem);
    struct page_entry *spte_b = hash_entry(b, struct page_entry, elem);
    return spte_a->vaddr < spte_b->vaddr;
}

struct page_entry *spte_create(uint8_t type, void *vaddr, bool writable, bool is_loaded, struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes) {
    struct page_entry *spte = (struct page_entry *)malloc(sizeof(struct page_entry));
    if (spte == NULL)
    {
        return NULL;
    }
    spte->type = type;
    spte->vaddr = vaddr;
    spte->writable = writable;
    spte->is_loaded = is_loaded;
    spte->file = file;
    spte->offset = offset;
    spte->read_bytes = read_bytes;
    spte->zero_bytes = zero_bytes;
    spte->swap_slot = 0;
    return spte;
}

bool spte_insert(struct hash *SPT, struct page_entry *spte) {
    struct hash_elem *result = hash_insert(SPT, &spte->elem);
    return result != NULL;
}

bool spte_delete(struct hash *SPT, struct page_entry *spte) {
    lock_acquire(&ft_lock);
    struct hash_elem *result = hash_delete(SPT, &spte->elem);
    if (result != NULL)
    {
        free_frame(pagedir_get_page(thread_current()->pagedir, spte->vaddr));
        free(spte);
        lock_release(&ft_lock);
        return true;
    }
    else {
        lock_release(&ft_lock);
        return false;
    }
}

struct page_entry *spte_find(void *vaddr) {
    struct page_entry spte;
    spte.vaddr = pg_round_down(vaddr);
    struct hash_elem *e = hash_find(&thread_current()->SPT, &spte.elem);
    if (e == NULL)
    {
        return NULL;
    }
    return hash_entry(e, struct page_entry, elem);
}

void spte_destroy_func(struct hash_elem *e, void *aux UNUSED) {
    struct page_entry *spte = hash_entry(e, struct page_entry, elem);
    lock_acquire(&ft_lock);
    if(spte){
        if(spte->is_loaded){
            free_frame(pagedir_get_page(thread_current()->pagedir, spte->vaddr));
        }
        free(spte);
    }
    lock_release(&ft_lock);
}

void SPT_destroy(struct hash *SPT) {
    hash_destroy(SPT, spte_destroy_func);
}

bool load_file(void *addr, struct page_entry *spte) {
    lock_acquire(&file_rw);
    file_seek(spte->file, spte->offset);
    off_t read_bytes = file_read_at(spte->file, addr, spte->read_bytes, spte->offset);
    lock_release(&file_rw);
    if (read_bytes != (off_t)spte->read_bytes)
    {
        return false;
    }
    memset(addr + spte->read_bytes, 0, spte->zero_bytes);
    return true;
}

