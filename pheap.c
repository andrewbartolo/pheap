#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

// desired heap size in bytes, including backing metadata.  Actual heap size may
// be slightly greater due to imperfect chunk alignment
#define DESIRED_HEAP_SIZE 1024000
#define BACKING_FILE "./backing_file"
#define MAGIC_NUMBER 0xBAADBAADCAFEF00D

#define PAYLOAD_CHUNKS(size) ((size / sizeof(mem_chunk_hdr_t)) + ((0 == size % \
                             sizeof(mem_chunk_hdr_t)) ? 0 : 1))
#define PAYLOAD_SIZE(size) (PAYLOAD_CHUNKS(size) * sizeof(mem_chunk_hdr_t))
#define COMPLETE_CHUNKS(size) (PAYLOAD_CHUNKS(size) + 1)
#define COMPLETE_SIZE(size) (COMPLETE_CHUNKS(size) * sizeof(mem_chunk_hdr_t))

/* for simplicity the size of this next struct is the basic unit
   of allocation in persistent heap; its size defines alignment */
typedef struct mem_chunk_hdr {
  size_t size;                           /* size of this chunk's PAYLOAD ONLY, in bytes */
  struct mem_chunk_hdr *next;            /* ptr to the next block in the free list */
} mem_chunk_hdr_t;

// the struct below defines the complete mmaped backing_file
typedef struct pheap {
  // note - handle must remain the first member of the struct in order to be read by the "locate handle" mmap call
  uint64_t magic_number;
  struct pheap *handle;           /* ptr to the start of the entire persistent heap */
  mem_chunk_hdr_t *freelist;      /* ptr to the first block in the freelist */
  mem_chunk_hdr_t heap[COMPLETE_CHUNKS(DESIRED_HEAP_SIZE)];
} pheap_t;

static pheap_t *handle;  // entry point for the current mmaping of the heap
static long pagesize;  // should this be a member of pheap_t instead?


/**
 * Sets up the persistent heap for first, or subsequent, use.
 * Upon first invocation, if desired_start_ptr == NULL, the kernel
 * chooses a location for the heap.  Otherwise, the handle stored at
 * offset `sizeof(magic_number)` is used.
 */
void pheap_init(void *desired_start_ptr) {
  bool heap_exists;
  int backing_file_fd;

  pagesize = sysconf(_SC_PAGESIZE);

  // check if backing_file exists (first time using heap?)
  heap_exists = (0 == access(BACKING_FILE, R_OK | W_OK | X_OK));
  backing_file_fd = open(BACKING_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR
                         | S_IXUSR);
  if (!heap_exists) {
    posix_fallocate(backing_file_fd, 0, sizeof(pheap_t));
 
    // needs to be MAP_SHARED to be able to msync() back to the file
    // TODO - benchmark trap time using gettimeofday() - expect time in us
    handle = (pheap_t *)mmap(desired_start_ptr, sizeof(pheap_t), PROT_READ | PROT_WRITE
                            | PROT_EXEC, MAP_SHARED, backing_file_fd, 0);

    handle->magic_number = MAGIC_NUMBER;
    handle->handle = handle;
    handle->heap[0].size = PAYLOAD_SIZE(DESIRED_HEAP_SIZE);
    // TODO - may not need this or below if fallocate zeroes bytes anyway
    handle->heap[0].next = NULL;
    // upon first invocation, first (and only) free block is at offset 0x0
    handle->freelist = handle->heap;
    msync(handle, sizeof(pheap_t), MS_SYNC);
  }
  else {
    pheap_t *initial_check = mmap(NULL, sizeof(uint64_t) + sizeof(pheap_t *), PROT_READ, MAP_PRIVATE, backing_file_fd, 0);
    assert(*(uint64_t *)initial_check == MAGIC_NUMBER);
    handle = *(pheap_t **)((char *)initial_check + sizeof(uint64_t));
    munmap(initial_check, sizeof(uint64_t) + sizeof(pheap_t *));

    mmap(handle, sizeof(pheap_t), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED,
         backing_file_fd, 0);
  }
}

/**
 * Uses a first-fit strategy to allocate chunks of memory.
 * When some block's next pointer is null, we have reached
 * the end of the freelist.
 */
void *pmalloc(size_t size) {
  // cannot malloc a chunk of size 0, nor if no free chunks available
  if (0 == size || NULL == handle->freelist) return NULL;

  // takes possible partially-filled chunk into account
  size_t needed_size = PAYLOAD_SIZE(size);

  mem_chunk_hdr_t *prev = NULL, *curr = handle->freelist;    // TODO - initialize/declare prev later on?

  // find a large-enough chunk
  while (curr->size < needed_size) {
    if (NULL == curr->next) return NULL;      // traversed entire free list; couldn't find large-enough block
    prev = curr;
    curr = curr->next;
  }

  // if we've gotten here, a suitably-sized chunk has been found

  size_t excess_size = curr->size - needed_size;
  // prepend possible excess from chunk back into the free list
  if (0 == excess_size) { 
    if (handle->freelist == curr) {    // if first block in freelist
        handle->freelist = curr->next;
    }
    else {
      prev->next = curr->next;
    }
  }

  // if we have enough room left for more than just a header (small optimization so that 0-sized chunks do not get added into the freelist)
  else if (excess_size >= (2 * sizeof(mem_chunk_hdr_t))) {
    // split the chunk, adding the unneeded space back into the freelist in place of curr (don't prepend).  TODO - prepend instead?
    mem_chunk_hdr_t *new_chunk = (mem_chunk_hdr_t *)((char *)curr + sizeof(mem_chunk_hdr_t) + needed_size);
    new_chunk->size = excess_size - sizeof(mem_chunk_hdr_t);
    curr->size = needed_size;

    if (handle->freelist == curr) {   // if curr was first block in freelist
      handle->freelist = new_chunk;
    }
    else {
      prev->next = new_chunk;
    }
    new_chunk->next = curr->next;
  }

  return 1 + curr;    // return a pointer to the payload
}

// prepends the newly-freed block to the freelist.  basic; does not coalesce.
void pfree(void *ptr) {
  mem_chunk_hdr_t *newly_freed = (mem_chunk_hdr_t *)ptr - 1;
  newly_freed->next = handle->freelist;
  handle->freelist = newly_freed;
}

// naive; syncs entire mapping (rather than just dirty pages)
void psync() {
  msync(handle, sizeof(pheap_t), MS_SYNC);
}

void pheap_test_basic() {
  // need to check if freelist == 0x0 or not
  void *foo0 = pmalloc(2048);
  printf("cleared 0\n");

  strcpy((char *)foo0, "string ONE");
  psync();

  void *foo1 = pmalloc(4096);
  printf("cleared 1\n");

  strcpy((char *)foo1, "string TWO");
  psync();
  
  void *foo2 = pmalloc(8192);
  printf("cleared 2\n");

  strcpy((char *)foo2, "string THREE");
  psync();

  pfree(foo0);
  pfree(foo1);
  pfree(foo2);
  psync();
  
}

// void pheap_test_basic_powers_of_2() {
//   size_t num_powers = 16;
//   void *ptrs[num_powers];

//   for (int i = 0; i < num_powers; ++i) {
//     printf("allocing 2^%d bytes\n", i);
//     size_t size_to_alloc = 1 << i;
//     ptrs[i] = pmalloc(size_to_alloc);
//   }
//   psync();  // ensure all changes are written to the heap
// }

void pheap_test_medium_write_strings(void *ptrs[], size_t num_ptrs) {
  for (int i = 0; i < num_ptrs; ++i) {
    size_t size_to_alloc = 1 << i;
    ptrs[i] = pmalloc(size_to_alloc);
    memset(ptrs[i], 97 + i, size_to_alloc);
    printf("alloced and filled %zi bytes with character %c, payload starting at %p\n",
           size_to_alloc, 97 + i, ptrs[i]);
  }

  psync();
}

void pheap_test_medium_write_strings_reuse(void *ptrs[], size_t num_ptrs) {
  for (int i = num_ptrs - 1; i >= 0; --i) {
    size_t size_to_alloc = 1 << i;
    ptrs[i] = pmalloc(size_to_alloc);
    memset(ptrs[i], 97 + i, size_to_alloc);
    printf("alloced and filled %zi bytes with character %c, payload starting at %p\n",
           size_to_alloc, 97 + i, ptrs[i]);
  }

  psync();
}

void pheap_test_medium_free(void *ptrs[], size_t num_ptrs) {
  for (int i = 0; i < num_ptrs; ++i) {
    pfree(ptrs[i]);
    printf("freed pointer: %p\n", ptrs[i]);
  }

  psync();
}

void pheap_test_medium_read_strings() {
  printf("%.8s\n", (char *)0x7fdeaceea068);
}

/**
 * Initializes the heap (setup-upon-first-run logic is still contained within
 * pheap_init()), then runs a series of unit tests.
 */
int main(int argc, char *argv[]) {
  // pheap_init's argument set to definite address for testing purposes.
  // can be null in practice.  need to cast literal to a void *.
  pheap_init((void *)0x7fdeaceea000);

  bool mode_write = (NULL != argv[1] && !strcmp("-w", argv[1]));

  if (mode_write) {

    for (int i = 0; i < 10; ++i) {
      size_t num_ptrs = 16;
      void *ptrs[num_ptrs];

      pheap_test_medium_write_strings_reuse(ptrs, num_ptrs);
      pheap_test_medium_free(ptrs, num_ptrs);
    }

  }
  else {
    pheap_test_medium_read_strings();
  }


  //printf("backing file fd: %d\n", backing_file_fd);
  printf("mmap handle: %p\n", (void *)handle);
  printf("freelist points to: %p\n", (void *)(handle->freelist));
  printf("page size: %li\n", pagesize);

  return 0;
}