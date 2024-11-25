#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"

#define SPTE_BIN 0 // binary file로부터 load된 data (can be lazy loaded)
#define SPTE_FILE 1 // file memory mapping으로부터 load된 data
#define SPTE_SWAP 2 // swap partition으로부터 load된 data (must be immediately loaded)

struct page_entry {
	uint8_t type; // entry type: SPTE_BIN, SPTE_FILE, SPTE_SWAP
	void *vaddr; // virtual page address
	bool writable; // 0: read-only, 1: writable
	bool is_loaded; // 0: not loaded to memory, 1: loaded to memory
	struct file* file; // file pointer
	size_t offset; // file offset
	size_t read_bytes; // read bytes
	size_t zero_bytes; // zero bytes
    struct hash_elem elem; // hash_elem variable for hash table
    struct list_elem mmap_elem; // list_elem variable for mmap list
    size_t swap_slot; // swap slot number
	//struct frame *frame; // frame pointer
};

struct mmap_file {
  mapid_t mapping_id;        
  struct file* file;     
  struct list_elem elem; 
  struct list spte_list;  
};

void SPT_init (struct hash *SPT);
struct page_entry *spte_create (uint8_t type, void *vaddr, bool writable, bool is_loaded, struct file *file, size_t offset, size_t read_bytes, size_t zero_bytes);
bool spte_insert (struct hash *SPT, struct page_entry *spte);
bool spte_delete (struct hash *SPT, struct page_entry *spte);
struct page_entry *spte_find(void *vaddr);
void spte_destroy_func(struct hash_elem *e, void *aux UNUSED);
void SPT_destroy (struct hash *SPT);
bool load_file (void *addr, struct page_entry *spte);

#endif