#define _LARGEFILE64_SOURCE
#include <stdbool.h>
#include <stdio.h>

//#define DBGPRINT(fmt...) fprintf(stderr, fmt)
#define DBGPRINT(fmt...) (0)


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;

static unsigned long  kallsyms_in_memory_num_syms;
static unsigned long *kallsyms_in_memory_addresses;
static uint8_t       *kallsyms_in_memory_names;
static uint8_t       *kallsyms_in_memory_token_table;
static uint16_t      *kallsyms_in_memory_token_index;
static unsigned long *kallsyms_in_memory_markers;

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * given the offset to where the symbol is in the compressed stream.
 */
static unsigned int
kallsyms_in_memory_expand_symbol(unsigned int off, char *result)
{
  int len, skipped_first = 0;
  const uint8_t *tptr, *data;

  /* Get the compressed symbol length from the first symbol byte. */
  data = &kallsyms_in_memory_names[off];
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
    tptr = &kallsyms_in_memory_token_table[kallsyms_in_memory_token_index[*data]];
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
kallsyms_in_memory_lookup_name(const char *name)
{
  char namebuf[1024];
  unsigned long i;
  unsigned int off;

  for (i = 0, off = 0; i < kallsyms_in_memory_num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(off, namebuf);
    if (strcmp(namebuf, name) == 0) {
      return kallsyms_in_memory_addresses[i];
    }
  }
  return 0;
}

/* Lookup the symbol for this address. Returns NULL if not found. */
const char *
kallsyms_in_memory_lookup_address(unsigned long address)
{
  static char namebuf[1024];
  unsigned long i;
  unsigned int off;

  for (i = 0, off = 0; i < kallsyms_in_memory_num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(off, namebuf);
    if (kallsyms_in_memory_addresses[i] == address) {
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
get_kallsyms_in_memory_addresses(unsigned long *mem, unsigned long length, unsigned long offset)
{
  unsigned long *addr = mem;
  unsigned long *end = (unsigned long*)((unsigned long)mem + length);

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

    kallsyms_in_memory_addresses = addr;
    DBGPRINT("[+]kallsyms_in_memory_addresses=%08x\n", (unsigned int)kallsyms_in_memory_addresses + (unsigned int)offset);

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

    kallsyms_in_memory_num_syms = addr[0];
    addr++;
    if (addr >= end) {
      return 0;
    }
    DBGPRINT("[+]kallsyms_in_memory_num_syms=%08x\n", (unsigned int)kallsyms_in_memory_num_syms);

    // check kallsyms_in_memory_num_syms
    if (kallsyms_in_memory_num_syms != n) {
      continue;
    }

    // skip there is filled by 0x0
    while (addr[0] == 0x00000000) {
      addr++;
      if (addr >= end) {
        return 0;
      }
    }

    kallsyms_in_memory_names = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_in_memory_names=%08x\n", (unsigned int)kallsyms_in_memory_names + (unsigned int)offset);

    // search end of kallsyms_in_memory_names
    unsigned int off;
    for (i = 0, off = 0; i < kallsyms_in_memory_num_syms; i++) {
      int len = kallsyms_in_memory_names[off];
      off += len + 1;
      if (&kallsyms_in_memory_names[off] >= (uint8_t*)end) {
        return 0;
      }
    }

    // adjust
    addr = (unsigned long*)((((unsigned long)&kallsyms_in_memory_names[off]-1)|0x3)+1);
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

    kallsyms_in_memory_markers = addr;
    DBGPRINT("[+]kallsyms_in_memory_markers=%08x\n", (unsigned int)kallsyms_in_memory_markers + (unsigned int)offset);

    // end of kallsyms_in_memory_markers
    addr = &kallsyms_in_memory_markers[((kallsyms_in_memory_num_syms-1)>>8)+1];
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

    kallsyms_in_memory_token_table = (uint8_t*)addr;
    DBGPRINT("[+]kallsyms_in_memory_token_table=%08x\n", (unsigned int)kallsyms_in_memory_token_table + (unsigned int)offset);

    // search end of kallsyms_in_memory_token_table
    i = 0;
    while (kallsyms_in_memory_token_table[i] != 0x00 || kallsyms_in_memory_token_table[i+1] != 0x00) {
      i++;
      if (&kallsyms_in_memory_token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // skip there is filled by 0x0
    while (kallsyms_in_memory_token_table[i] == 0x00) {
      i++;
      if (&kallsyms_in_memory_token_table[i-1] >= (uint8_t*)end) {
        return 0;
      }
    }

    // but kallsyms_in_memory_markers shoud be start 0x0000
    kallsyms_in_memory_token_index = (uint16_t*)&kallsyms_in_memory_token_table[i-2];
    DBGPRINT("[+]kallsyms_in_memory_token_index=%08x\n", (unsigned int)kallsyms_in_memory_token_index + (unsigned int)offset);

    return 1;
  }
  return 0;
}

bool
kallsyms_in_memory_init(unsigned long *mem, size_t len)
{
  unsigned long mmap_offset = 0xc0008000 - (unsigned long)mem;
  DBGPRINT("[+]mmap\n");
  DBGPRINT("  mem=%08x length=%08x offset=%08x\n", (unsigned int)mem, (unsigned int)len, (unsigned int)mmap_offset);

  int ret = get_kallsyms_in_memory_addresses(mem, len, mmap_offset);
  if (!ret) {
    fprintf(stderr, "kallsyms_in_memory_addresses search failed\n");
    return false;
  }

  //kallsyms_in_memory_print_all();
  DBGPRINT("[+]kallsyms_in_memory_lookup_name\n");

  return true;
}

bool
is_address_in_kallsyms_table(void *mapped_address)
{
  DBGPRINT("check %p <= %p <= %p\n",
           kallsyms_in_memory_addresses, mapped_address, &kallsyms_in_memory_addresses[kallsyms_in_memory_num_syms]);

  if (mapped_address < (void *)kallsyms_in_memory_addresses)
    return false;

  if (mapped_address > (void *)&kallsyms_in_memory_addresses[kallsyms_in_memory_num_syms])
    return false;

  return true;
}

void
kallsyms_in_memory_print_all(void)
{
  char namebuf[1024];
  unsigned long i;
  unsigned int off;

  for (i = 0, off = 0; i < kallsyms_in_memory_num_syms; i++) {
    off = kallsyms_in_memory_expand_symbol(off, namebuf);
    printf("%08x %s\n", (unsigned int)kallsyms_in_memory_addresses[i], namebuf);
  }
  return;
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
