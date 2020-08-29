/// @file

#ifndef LIBMPATCH_MPATCH_H
#define LIBMPATCH_MPATCH_H

#include <stddef.h>
#include <stdint.h>

// I'm generally against doing this but The compiler barks about
// mp_get_proc_list's definition not matching between the header and source
// file without this for some reason.
typedef struct kinfo_proc kinfo_proc;

/**
 * Word-aligns a given size.
 *
 * @param size the size to word-align
 * @return the word-aligned size
 */
size_t mp_word_align(size_t size);

/**
 * Reads \p len bytes from the memory of the process with the ID of \p pid,
 * starting at \p addr.
 *
 * Be aware that \p addr is absolute, so if you are attempting to read data at
 * a specific file offset, you will first need to add the offset to the base
 * address of the process due to ASLR. See mp_get_proc_base_addr().
 *
 * @param pid the ID of the target process
 * @param addr the address to start reading from
 * @param len the number of bytes to read
 */
unsigned char *mp_read(int pid, void *addr, size_t len);

/**
 * Writes \p len bytes from the buffer \p data to the memory of the process
 * with the ID of \p pid, starting at \p addr.
 *
 * @param pid the ID of the process to read from
 * @param addr the address to start reading at
 * @param data the buffer of bytes to write
 * @param len the number of bytes to write (should be the length of \p data)
 * @return the Mach error code indicating the success/failure of the operation
 */
int mp_write(int pid, void *addr, unsigned char *data, size_t len);

/**
 * Gets the process ID of the process with the given name.
 *
 * @param name the name of the process to find
 */
int32_t mp_get_pid(char *name);

/**
 * Gets a list of all running processes.
 *
 * @param [out] list the list of running processes
 * @param [out] count the length of \p list (number of processes)
 * @return the Mach error code indicating the success/failure of the operation
 */
static int mp_get_proc_list(kinfo_proc **list, size_t *count);

/**
 * Gets the base address (post-ASLR) of the process with the ID of \p pid.
 *
 * This function will be necessary if attempting to patch memory based off of
 * known file offsets. First get the base address, then add the offset to the
 * return value of this function.
 *
 * @param pid the ID of the process to read from
 * @return the base address of the process
 */
uint64_t mp_get_proc_base_addr(int pid);

#endif
