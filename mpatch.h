// libmpatch
// https://github.com/jonpalmisc/libmpatch
//
// MIT License
//
// Copyright (c) 2020 Jon Palmisciano
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// @file

#ifndef LIBMPATCH_MPATCH_H
#define LIBMPATCH_MPATCH_H

#include <stddef.h>
#include <stdint.h>

#define MP_ERR_SUCCESS 0x00
#define MP_ERR_MALLOC 0x01
#define MP_ERR_GET_TASK 0x02
#define MP_ERR_VM_READ 0x03
#define MP_ERR_VM_PROTECT 0x04
#define MP_ERR_VM_WRITE 0x05
#define MP_ERR_VM_RECURSE 0x06

typedef int mp_return;

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
 * @param [out] dest the buffer to read to
 * @param len the number of bytes to read
 * @return the status code indicating the success/failure of the operation
 */
mp_return mp_read(int pid, void *addr, unsigned char **dest, size_t len);

/**
 * Writes \p len bytes from the buffer \p data to the memory of the process
 * with the ID of \p pid, starting at \p addr.
 *
 * @param pid the ID of the process to read from
 * @param addr the address to start reading at
 * @param data the buffer of bytes to write
 * @param len the number of bytes to write (should be the length of \p data)
 * @return the status code indicating the success/failure of the operation
 */
mp_return mp_write(int pid, void *addr, unsigned char *data, size_t len);

/**
 * Gets the base address (post-ASLR) of the process with the ID of \p pid.
 *
 * This function will be necessary if attempting to patch memory based off of
 * known file offsets. First get the base address, then add the offset to the
 * return value of this function.
 *
 * @param pid the ID of the process to read from
 * @param [out] base_addr the location to write the base address
 * @return the status code indicating the success/failure of the operation
 */
mp_return mp_get_proc_base_addr(int pid, uint64_t *base_addr);

#endif
