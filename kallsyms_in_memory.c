#define _LARGEFILE64_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "kallsyms_in_memory.h"

static bool verbose_output;

#define DBGPRINT(fmt...) do { if (verbose_output) { fprintf(stderr, fmt); } } while (0)

#define ARRAY_SIZE(n) (sizeof (n) / sizeof (*n))

struct _kallsyms {
  unsigned long  num_syms;
  unsigned long *addresses;
  uint8_t       *names;
  uint8_t       *token_table;
  uint16_t      *token_index;
  unsigned long *markers;
};

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * given the offset to where the symbol is in the compressed stream.
 */
static unsigned int
kallsyms_in_memory_expand_symbol(kallsyms *kallsyms, unsigned int off, char *result)
{
  int len, skipped_first = 0;
  const uint8_t *tptr, *data;

  /* Get the compressed symbol length from the first symbol byte. */
  data = &kallsyms->names[off];
  len = *data;
  data++;

  /*
   * Update the offset to return the offset for the next symbol on
   * the compressed stream.
   */
  off += len + 1;

  /*
   * For every byte on the compressed symbol data, copy the table
   * entry for that byte.
   */
  while (len) {
    tptr = &kallsyms->token_table[kallsyms->token_index[*data]];
    data++;
    len--;

    while (*tptr) {
      if (skipped_first) {
        *result = *tptr;
        result++;
      }
      else {
        skipped_first = 1;
      }

      tptr++;
    }
  }

  *result = '\0';

  /* Return to offset to the next symbol. */
  return off;
}

/* Lookup the address for this symbol. Returns 0 if not found. */
unsigned long
kallsyms_in_memory_lookup_name(kallsyms *kallsyms, const char *name)
{
  char namebuf[1024];
  unsigned long i;
  unsigned int off;

  if (!kallsyms) {
    return 0;
  }

  for (i = 0, off = 0; i < kallsyms->num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(kallsyms, off, namebuf);
    if (strcmp(namebuf, name) == 0) {
      return kallsyms->addresses[i];
    }
  }
  return 0;
}

bool
kallsyms_in_memory_lookup_names(kallsyms *kallsyms, const char *name,
                                unsigned long *addresses, size_t n_addresses)
{
  char namebuf[1024];
  unsigned long i, count;
  unsigned int off;

  if (!kallsyms) {
    return false;
  }

  for (i = 0, off = 0, count = 0;
       i < kallsyms->num_syms && count < n_addresses;
       i++) {
    off = kallsyms_in_memory_expand_symbol(kallsyms, off, namebuf);
    if (strcmp(namebuf, name) == 0) {
      addresses[count] = kallsyms->addresses[i];
      count++;
    }
  }
  if (!count) {
    return false;
  }

  return true;
}

/* Lookup the symbol for this address. Returns NULL if not found. */
const char *
kallsyms_in_memory_lookup_address(kallsyms *kallsyms, unsigned long address)
{
  static char namebuf[1024];
  unsigned long i;
  unsigned int off;

  if (!kallsyms) {
    return NULL;
  }

  for (i = 0, off = 0; i < kallsyms->num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(kallsyms, off, namebuf);
    if (kallsyms->addresses[i] == address) {
      return namebuf;
    }
  }
  return NULL;
}

static const unsigned long const pattern_kallsyms_in_memory_addresses_1[] = {
  0xc0008000, // __init_begin
  0xc0008000, // _sinittext
  0xc0008000, // stext
  0xc0008000, // _text
  0
};

static const unsigned long const pattern_kallsyms_in_memory_addresses_2[] = {
  0xc0008000, // stext
  0xc0008000, // _text
  0
};

static const unsigned long const pattern_kallsyms_in_memory_addresses_3[] = {
  0xc00081c0, // asm_do_IRQ
  0xc00081c0, // _stext
  0xc00081c0, // __exception_text_start
  0
};

static const unsigned long const pattern_kallsyms_in_memory_addresses_4[] = {
  0xc0008180, // asm_do_IRQ
  0xc0008180, // _stext
  0xc0008180, // __exception_text_start
  0
};

static const unsigned long const * const pattern_kallsyms_in_memory_addresses[] = {
  pattern_kallsyms_in_memory_addresses_1,
  pattern_kallsyms_in_memory_addresses_2,
  pattern_kallsyms_in_memory_addresses_3,
  pattern_kallsyms_in_memory_addresses_4,
};

static unsigned long *
search_pattern(unsigned long *base, unsigned long count, const unsigned long *const pattern)
{
  unsigned long *addr = base;
  unsigned long i;
  int pattern_count;

  for (pattern_count = 0; pattern[pattern_count]; pattern_count++) {
    ;
  }

  for (i = 0; i < count - pattern_count; i++) {
    if(addr[i] != pattern[0]) {
      continue;
    }

    if (memcmp(&addr[i], pattern, sizeof (pattern[0]) * pattern_count) == 0) {
      return &addr[i];
    }
  }
  return 0;
}

static int
get_kallsyms_in_memory_addresses(kallsyms *kallsyms, unsigned long *mem, unsigned long length, unsigned long offset)
{
  unsigned long *addr = mem;
  unsigned long *end = (unsigned long*)((unsigned long)mem + length);

  if (!kallsyms) {
    return -1;
  }

  while (addr < end) {
    unsigned long *search = addr;
    unsigned long i;

    // get kallsyms_in_memory_addresses pointer
    for (i = 0; i < sizeof (pattern_kallsyms_in_memory_addresses) / sizeof (pattern_kallsyms_in_memory_addresses[0]); i++) {
      addr = search_pattern(search, end - search, pattern_kallsyms_in_memory_addresses[i]);
      if (addr) {
        break;
      }
    }

    if (!addr) {
        return 0;
    }

    kallsyms->addresses = addr;
    DBGPRINT("[+]kallsyms_in_memory_addresses=%08x\n", (unsigned int)kallsyms->addresses + (unsigned int)offset);

    // search end of kallsyms_in_memory_addresses
    unsigned long n=0;
    while (addr[0] > 0xc0000000) {
      n++;
      addr++;
      if (addr >= end) {
        return 0;
      }
    }
    DBGPRINT("  count=%08x\n", (unsigned int)n);

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms->num_syms = addr[0];
    addr++;
    if (addr >= end) {
      return 0;
    }
    DBGPRINT("[+]kallsyms_in_memory_num_syms=%08x\n", (unsigned int)kallsyms->num_syms);

    // check kallsyms_in_memory_num_syms
    if (kallsyms->num_syms != n) {
      continue;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms->names = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_in_memory_names=%08x\n", (unsigned int)kallsyms->names + (unsigned int)offset);

    // search end of kallsyms_in_memory_names
    unsigned int off;
    for (i = 0, off = 0; i < kallsyms->num_syms; i++) {
      int len = kallsyms->names[off];
      off += len + 1;
      if (&kallsyms->names[off] >= (uint8_t*)end) {
        return 0;
      }
    }

    // adjust
    addr = (unsigned long*)((((unsigned long)&kallsyms->names[off]-1)|0x3)+1);
    if (addr >= end) {
      return 0;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }
    // but kallsyms_in_memory_markers shoud be start 0x00000000
    addr--;

    kallsyms->markers = addr;
    DBGPRINT("[+]kallsyms_in_memory_markers=%08x\n", (unsigned int)kallsyms->markers + (unsigned int)offset);

    // end of kallsyms_in_memory_markers
    addr = &kallsyms->markers[((kallsyms->num_syms-1)>>8)+1];
    if (addr >= end) {
      return 0;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms->token_table = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_in_memory_token_table=%08x\n", (unsigned int)kallsyms->token_table + (unsigned int)offset);

    // search end of kallsyms_in_memory_token_table
    i = 0;
    while (kallsyms->token_table[i] != 0x00 || kallsyms->token_table[i+1] != 0x00) {
      i++;
      if (&kallsyms->token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // skip there is filled by 0x0
    while (kallsyms->token_table[i] == 0x00) {
      i++;
      if (&kallsyms->token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // but kallsyms_in_memory_markers shoud be start 0x0000
    kallsyms->token_index = (uint16_t*)&kallsyms->token_table[i-2];
    DBGPRINT("[+]kallsyms_in_memory_token_index=%08x\n", (unsigned int)kallsyms->token_index + (unsigned int)offset);

    return 1;
  }
  return 0;
}

kallsyms *
kallsyms_in_memory_init(unsigned long *mem, size_t len)
{
  kallsyms *kallsyms;
  unsigned long mmap_offset = 0xc0008000 - (unsigned long)mem;
  DBGPRINT("[+]mmap\n");
  DBGPRINT("  mem=%08x length=%08x offset=%08x\n", (unsigned int)mem, (unsigned int)len, (unsigned int)mmap_offset);

  kallsyms = calloc(sizeof(kallsyms), 1);
  int ret = get_kallsyms_in_memory_addresses(kallsyms, mem, len, mmap_offset);
  if (!ret) {
    fprintf(stderr, "kallsyms_in_memory_addresses search failed\n");
    free(kallsyms);
    return NULL;
  }

  //kallsyms_in_memory_print_all();
  DBGPRINT("[+]kallsyms_in_memory_lookup_name\n");

  return kallsyms;
}

static bool
is_address_in_kallsyms_table(kallsyms *kallsyms, void *mapped_address)
{
  DBGPRINT("check %p <= %p <= %p\n",
           kallsyms->addresses, mapped_address, &kallsyms->addresses[kallsyms->num_syms]);

  if (mapped_address < (void *)kallsyms->addresses)
    return false;

  if (mapped_address > (void *)&kallsyms->addresses[kallsyms->num_syms])
    return false;

  return true;
}

void
kallsyms_in_memory_print_all_to_file(kallsyms *kallsyms, FILE *fp)
{
  char namebuf[1024];
  unsigned long i;
  unsigned int off;

  if (!kallsyms) {
    return;
  }

  for (i = 0, off = 0; i < kallsyms->num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(kallsyms, off, namebuf);
    fprintf(fp, "%08x %s\n", (unsigned int)kallsyms->addresses[i], namebuf);
  }
  return;
}

void
kallsyms_in_memory_print_all(kallsyms *kallsyms)
{
  if (!kallsyms) {
    return;
  }
  kallsyms_in_memory_print_all_to_file(kallsyms, stdout);
}

void
kallsyms_in_memory_set_verbose(bool verbose)
{
  verbose_output = verbose;
}

void
kallsyms_in_memory_free(kallsyms *kallsyms)
{
  if (kallsyms) {
    free(kallsyms);
  }
}

#if 0
static bool
do_kallsyms_in_memory(void)
{
  bool ret;
  void *address;

  if (!map_kernel_memory()) {
    printf("Failed to mmap due to %s.\n", strerror(errno));

    return false;
  }

  address = convert_to_kernel_mapped_address((void *)0xc0008000);
  ret = get_kallsyms_in_memory(address, KERNEL_MEMORY_SIZE);

  unmap_kernel_memory();
  return ret;
}

int
main(int argc, char **argv)
{
  if (!do_kallsyms_in_memory()) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
#endif
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
