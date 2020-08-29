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

#include <mach-o/dyld.h>
#include <mach/host_info.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/mach_vm.h>
#include <mach/shared_region.h>

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/sysctl.h>

void _mp_print_err(char *func, char *msg) {
  printf("[%s] Error: %s\n", func, msg);
}

size_t mp_word_align(size_t size) {
  size_t rsize = 0;

  rsize =
      ((size % sizeof(long)) > 0) ? (sizeof(long) - (size % sizeof(long))) : 0;
  rsize += size;

  return rsize;
}

mp_return mp_read(int pid, void *addr, unsigned char **dest, size_t len) {
  assert(len != 0 || addr != 0);

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
  assert(len != 0 || addr != 0 || data != 0);

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

uint64_t mp_get_proc_base_addr(int pid) {

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    _mp_print_err("mp_get_proc_base_addr", "Failed to get task for PID.");
  }

  vm_map_size_t vm_size = 0;
  mach_vm_address_t base_addr = 0;
  natural_t depth = 0;

  struct vm_region_submap_info_64 region_info;
  mach_msg_type_number_t region_info_len = sizeof(region_info);

  kern_ret = mach_vm_region_recurse(task, &base_addr, &vm_size, &depth,
                                    (vm_region_recurse_info_t)&region_info,
                                    &region_info_len);
  if (kern_ret != KERN_SUCCESS) {
    return 0;
  }

  return base_addr;
}

// https://developer.apple.com/library/archive/qa/qa2001/qa1123.html
static int mp_get_proc_list(struct kinfo_proc **list, size_t *count) {
  int err;
  kinfo_proc *result;

  static const int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t name_len = (sizeof(name) / sizeof(*name)) - 1;

  size_t length;

  assert(list != NULL);
  assert(*list == NULL);
  assert(count != NULL);

  *count = 0;
  result = NULL;
  bool done = false;
  do {
    assert(result == NULL);

    // Call sysctl with a NULL buffer to get the right buffer size.
    length = 0;
    err = sysctl((int *)name, name_len, NULL, &length, NULL, 0);
    if (err == -1) {
      err = errno;
    }

    // Allocate an appropriately sized buffer based on the results
    // from the previous call.

    if (err == 0) {
      result = malloc(length);
      if (result == NULL) {
        err = ENOMEM;
      }
    }

    // Call sysctl again with the new buffer.  If we get an ENOMEM
    // error, toss away our buffer and start again.

    if (err == 0) {
      err = sysctl((int *)name, name_len, result, &length, NULL, 0);
      if (err == -1) {
        err = errno;
      }

      if (err == 0) {
        done = true;
      } else if (err == ENOMEM) {
        assert(result != NULL);
        free(result);
        result = NULL;

        err = 0;
      }
    }
  } while (err == 0 && !done);

  // Clean up and establish post conditions.

  if (err != 0 && result != NULL) {
    free(result);
    result = NULL;
  }

  *list = result;

  if (err == 0) {
    *count = length / sizeof(kinfo_proc);
  }

  assert((err == 0) == (*list != NULL));

  return err;
}

int32_t mp_get_pid(char *name) {

  // Retrieve the list of running processes.
  struct kinfo_proc *proc_list;
  size_t proc_count;
  mp_get_proc_list(&proc_list, &proc_count);

  // Iterate over each process and compare names.
  pid_t pid;
  for (int j = 0; j < proc_count + 1; j++) {
    if (strcmp(proc_list[j].kp_proc.p_comm, name) == 0)
      pid = proc_list[j].kp_proc.p_pid;
  }

  free(proc_list);
  return pid;
}
