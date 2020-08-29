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

#include <Foundation/Foundation.h>
#include <objc/runtime.h>

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "../mpatch.h"

@interface Example : NSObject
@end

@implementation Example

// This example program is meant to be compiled as a dynamic library and
// forcefully loaded using DYLD_INSERT_LIBRARIES. See dyld(1) for more info.
+ (void)load {

  // Gets the process ID of the current running process.
  int pid = getpid();

  // First we need to retrieve the base address of the process due to ASLR.
  uint64_t base_addr = mp_get_proc_base_addr(getpid());

  // By disassembling the program with Ghidra, we were able to find the code
  // which determines whether to show the software registration window. Below
  // is the file offset of the JNZ instruction which skips the registration
  // window if a license is found.
  uint64_t reg_wnd_offset = 0x887b88;

  // We can get the in-memory address of the JNZ instruction we are after by
  // adding the file offset to the process' base address.
  void *reg_wnd_addr = (void *)(base_addr + reg_wnd_offset);

  // Our memory reading/writing functions operate on word-aligned sizes. In this
  // instance we know the 2 bytes word-aligned is 4 bytes, but this is more of
  // a demonstration of the function which could come in handy when working with
  // larger or non-predetermined values.
  size_t patch_size = mp_word_align(sizeof(char) * 2);

  // Here we read the original memory of the process into a buffer.
  unsigned char *patched;
  mp_return err = mp_read(pid, reg_wnd_addr, &patched, patch_size);

  // We can check the result of the operation via the error code returned.
  if (err != MP_ERR_SUCCESS) {
    printf("Error: %s (%d)\n", "Failed to read process memory.", err);
  }

  // Next, we patch the first two bytes to change the JNZ instruction into a
  // JMP instruction, which will result in the registration window never being
  // shown, no matter what.
  patched[0] = 0x48;
  patched[1] = 0xE9;

  // Lastly, we write the patched bytes back into the process' memory.
  err = mp_write(pid, reg_wnd_addr, patched, patch_size);
  if (err != MP_ERR_SUCCESS) {
    printf("Error: %s (%d)\n", "Failed to write process memory.", err);
  }

  free(patched);
}

@end
