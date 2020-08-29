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

unsigned char *mp_read(int pid, void *addr, size_t len) {
  assert(len != 0 || addr != 0);

  // Word align our desired read length.
  len = mp_word_align(len);

  // Attempt to allocate a buffer to read into.
  unsigned char *data_buf = malloc(len);
  mach_msg_type_number_t data_len;
  if (data_buf == NULL) {
    _mp_print_err("mp_read", "Failed to allocate data buffer.");
  }

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    _mp_print_err("mp_read", "Failed to get task for PID.");
  }

  // Attempt to read the task's memory into out buffer.
  kern_ret = vm_read(task, (vm_address_t)addr, len, (vm_offset_t *)&data_buf,
                     &data_len);
  if (kern_ret != KERN_SUCCESS) {
    _mp_print_err("mp_read", "Failed to read task memory.");
    free(data_buf);
  }

  return data_buf;
}

kern_return_t mp_write(int pid, void *addr, unsigned char *data, size_t len) {
  assert(len != 0 || addr != 0 || data != 0);

  // Word align our desired write length.
  len = mp_word_align(len);

  // TODO: Remove copying if possible.
  unsigned char *data_cpy = (unsigned char *)malloc(len);
  if (data_cpy == NULL) {
    _mp_print_err("mp_write", "Failed to allocate data copy buffer.");
  }

  // Copy the data into our new buffer.
  memcpy(data_cpy, data, len);

  // Find the desired task by PID.
  mach_port_t task;
  kern_return_t kern_ret = task_for_pid(mach_task_self(), pid, &task);
  if (kern_ret != KERN_SUCCESS) {
    _mp_print_err("mp_write", "Failed to get task for PID.");
  }

  // Set address space permissions.
  vm_protect(task, (vm_address_t)addr, (vm_size_t)len, 0,
             VM_PROT_READ | VM_PROT_WRITE | VM_PROT_ALL);

  // Write memory!
  return vm_write(task, (vm_address_t)addr, (pointer_t)data_cpy, len);
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
