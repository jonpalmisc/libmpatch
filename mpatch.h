#ifndef LIBMPATCH_MPATCH_H
#define LIBMPATCH_MPATCH_H

#include <stddef.h>
#include <stdint.h>

#include <mach/error.h>

typedef struct kinfo_proc kinfo_proc;

// Word-aligns a given size/length.
size_t mp_word_align(size_t size);

// Reads a given process' memory.
unsigned char *mp_read(int pid, void *addr, size_t *len);

// Write to a given process' memory.
kern_return_t mp_write(int pid, void *addr, unsigned char *data, size_t len);

// Finds a process by name.
int32_t mp_get_pid(char *procname);
static int mp_get_proc_list(kinfo_proc **list, size_t *count);

int mp_set_page_exec(void *address);

#endif