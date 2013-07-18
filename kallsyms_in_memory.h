#ifndef __KALLSYMSPRINT_H__
#define __KALLSYMSPRINT_H__

#include <stdbool.h>

extern bool kallsyms_in_memory_init(unsigned long *mem, size_t len);

extern unsigned long kallsyms_in_memory_lookup_name(const char *name);
extern const char *kallsyms_in_memory_lookup_address(unsigned long address);

extern bool is_address_in_kallsyms_table(void *mapped_address);

extern void kallsyms_in_memory_print_all(void);

#endif /* __KALLSYMSPRINT_H__ */

/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
