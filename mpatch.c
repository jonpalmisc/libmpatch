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

#include "mpatch.h"

#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>
#include <mach-o/dyld.h>

#include <stdio.h>
#include <stdlib.h>

size_t mp_word_align(size_t size) {
  size_t pad = 0;
  if (size % sizeof(long) > 0) {
    pad = sizeof(long) - (size % sizeof(long));
  }

  return pad + size;
}

mp_return mp_read(int pid, void *addr, unsigned char **dest, size_t len) {
  if (len == 0 || addr == 0) {
    return MP_ERR_ARGS;
  }

  // Word align our desired read length.
  len = mp_word_align(len);

  // Attempt to allocate a buffer to read into.
  *dest = malloc(len);
  if (*dest == NULL) {
    return MP_ERR_MALLOC;
  }

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    return MP_ERR_GET_TASK;
  }

  // Attempt to read the task's memory into out buffer.
  mach_msg_type_number_t read;
  kern_ret = vm_read(task, (vm_address_t)addr, len, (vm_offset_t *)dest, &read);

  return kern_ret == KERN_SUCCESS ? MP_ERR_SUCCESS : MP_ERR_VM_READ;
}

mp_return mp_write(int pid, void *addr, unsigned char *data, size_t len) {
  if (len == 0 || addr == 0 || data == 0) {
    return MP_ERR_ARGS;
  }

  // Word align our desired write length.
  len = mp_word_align(len);

  // TODO: Remove copying if possible.
  unsigned char *data_cpy = (unsigned char *)malloc(len);
  if (data_cpy == NULL) {
    return MP_ERR_MALLOC;
  }

  // Copy the data into our new buffer.
  memcpy(data_cpy, data, len);

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    return MP_ERR_GET_TASK;
  }

  // Set address space permissions.
  kern_ret = vm_protect(task, (vm_address_t)addr, (vm_size_t)len, 0,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_ALL);
  if (kern_ret != KERN_SUCCESS) {
    return MP_ERR_VM_PROTECT;
  }

  // Write memory!
  kern_ret = vm_write(task, (vm_address_t)addr, (pointer_t)data_cpy, len);

  return kern_ret == KERN_SUCCESS ? MP_ERR_SUCCESS : MP_ERR_VM_WRITE;
}

mp_return mp_get_proc_base_addr(int pid, uint64_t *base_addr) {

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    return MP_ERR_GET_TASK;
  }

  struct vm_region_submap_info_64 region_info;
  mach_msg_type_number_t region_info_len = sizeof(region_info);

  vm_map_size_t vm_size = 0;
  natural_t depth = 0;
  kern_ret = mach_vm_region_recurse(task, base_addr, &vm_size, &depth,
                                    (vm_region_recurse_info_t)&region_info,
                                    &region_info_len);

  return kern_ret == KERN_SUCCESS ? MP_ERR_SUCCESS : MP_ERR_VM_RECURSE;
}
