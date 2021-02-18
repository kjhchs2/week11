/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

    uintptr_t pg_ptr = (uintptr_t)aux;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
        bool (*initializer)(struct page *, enum vm_type, void *kva);

        struct page *page = palloc_get_page(PAL_USER | PAL_ZERO);
        
        if (VM_TYPE(type) == VM_ANON)
            initializer = anon_initializer;
        else if (VM_TYPE(type) == VM_FILE) 
            initializer = file_backed_initializer;
        else
            goto err;
        uninit_new(page, upage, lazy_load_segment, type, pg_ptr, initializer);
       
		/* TODO: Create the page, fetch the initializer according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		
        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        이거 아직 안함
         * TODO: should modify the field after calling the uninit_new. */
        
		/* TODO: Insert the page into the spt. */
        spt_insert_page(spt, page);
	}
err:
	return false;
}

// //후보 1번 : PPT 방식
// /* Find VA from spt and return page. On error, return NULL. */
// struct page *
// spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
// 	struct page *page = NULL;
// 	/* TODO: Fill this function. */
//     struct hash_iterator i;

//     struct page* page_find = pg_round_down((uintptr_t*)va) // 이게 페이지가 맞는지 모르겠다. 주소값인거같다.
//     struct hash_elem* return_value = hash_find(&spt->pages, &page_find->hash_elem);
//     if (return_value == NULL)
//         return NULL
// 	else
//         return hash_entry(return_value, struct page, hash_elem);
// }

// 후보 2번 : 민규머리
/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
    struct hash_iterator i;

    hash_first(&i, &spt->pages);
    while (hash_next(&i))
    {
        page = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (page->va == va)
            return page;
    }
	return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
    struct hash_elem *he = hash_insert(&spt->pages, &page->hash_elem);
    if (he == NULL){
        succ = true;
    }
	return succ;
}

/* 무언가 하라는 말이 없는데 수정할 필요 없나?*/
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
    frame->page = palloc_get_page(PAL_ZERO | PAL_USER);


	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	이거 업데이트 필요
    * TODO: writeback all the modified contents to the storage. */
    
    // struct hash_iterator i;
    // hash_first(&i, &spt->pages);
    // while (hash_next(&i))
    // {
    //     destroy(hash_entry(hash_cur(&i), struct page, hash_elem));
    // }
    hash_destroy(&spt->pages, get_page_and_free);
}

void
get_page_and_free(struct hash_elem * he, void* aux){
    struct page *page = hash_entry(he, struct page, hash_elem);
    /*Clean up the associated Frame*/



    /*Clean up the associated Frame*/
    palloc_free_page(page);
}