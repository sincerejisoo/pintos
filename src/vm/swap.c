#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"

#include "threads/synch.h"
#include "threads/vaddr.h"

static struct lock swap_lock;
static struct bitmap *swap_bitmap;
static struct block *swap_block;
#define SEC_PER_PG (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init() {
	lock_init(&swap_lock);
	swap_block = block_get_role(BLOCK_SWAP);
	swap_bitmap = bitmap_create((size_t)(block_size(swap_block) / SEC_PER_PG));
}

bool swap_in(size_t slot_idx, void *kaddr) {
	int start_sector = slot_idx * SEC_PER_PG;
	for (int i = 0; i < SEC_PER_PG; i++) {	
		block_read(swap_block, start_sector + i, kaddr + i * BLOCK_SECTOR_SIZE);
	}
	lock_acquire(&swap_lock);
	bitmap_set(swap_bitmap, slot_idx, false);
    lock_release(&swap_lock);
	return true;
}

size_t swap_out(void* kaddr) {
    lock_acquire(&swap_lock);
	size_t slot_idx = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
	lock_release(&swap_lock);
	if(slot_idx == BITMAP_ERROR)
	{
		PANIC("swap partition full");
		return BITMAP_ERROR;
	}

	int start_sector = slot_idx * SEC_PER_PG;	
	for (int i = 0; i < SEC_PER_PG; i++) {
		block_write(swap_block, start_sector + i, kaddr + i * BLOCK_SECTOR_SIZE);
	}
	return slot_idx;
}