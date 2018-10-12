#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

typedef void (*FP)();

FP ICTarget = NULL;

// implement the indirct function call
void indirect_call()
{
	__asm__ ("jmp *ICTarget(%rip)\n\t");
}

void indirect_call_float () __attribute__ ((weak, alias ("indirect_call")));
void indirect_call_double () __attribute__ ((weak, alias ("indirect_call")));
void indirect_call_ldouble () __attribute__ ((weak, alias ("indirect_call")));
void indirect_call_vector () __attribute__ ((weak, alias ("indirect_call")));
void indirect_call_struct () __attribute__ ((weak, alias ("indirect_call")));

// just one return instruction
void aRet(unsigned long target)
{
	__asm__ (
			PARALLEL_SS
			);
}

// indirectly call the all-ret function ptwrite_chunk
void ptwrite(unsigned long target)
{
	__asm__ ("jmp *%rdi\n\t");
}

// all-ret function
void ptwrite_chunk()
{
    __asm__ (
			FILLRET
            );
}

#ifdef PARALLEL_SHADOW_STACK
extern void get_stack_bound(void **low_b, void **high_b, void **no_use);

asm (
    "\t.align 16, 0x90\n"
    "\t.type get_,@function\n"
    "get_stack_bound:\n"
    "\tmovq %rsp, %rdx\n"
    "\tcallq get_stack_high_b\n"
    "\tretq\n"
);

#define PAGE_SIZE       4096
#define STACK_SIZE      (8 * (1 << 20))
#define SS_OFFSET       (1UL << 31)

#define error(format, ...)                                          \
    do {                                                            \
        fprintf(stderr, "error: " format "\n", ##__VA_ARGS__);      \
        abort();                                                    \
    } while (false)

extern __attribute__((__noinline__)) void get_stack_high_b(
		void **low_b, void **high_b, void *fptr0)
{
    void *fptr = fptr0 - ((uintptr_t)fptr0 % PAGE_SIZE);
	*low_b = fptr;
    fptr += PAGE_SIZE;
    // mincore() will fail with ENOMEM for unmapped pages.  We can therefore
    // linearly scan to the base of the stack.
    // Note in practice this seems to be 1-3 pages at most if called from a
    // constructor.
    unsigned char vec;
    while (mincore(fptr, PAGE_SIZE, &vec) == 0)
        fptr += PAGE_SIZE;
    if (errno != ENOMEM)
        error("failed to mincore page: %s", strerror(errno));
	*high_b = fptr;

	return;
}

__attribute__((constructor(123))) void ucfi_init()
{
	void *stack_low, *stack_high, *new_stack_low;
	get_stack_bound(&stack_low, &stack_high, &stack_low);
    size_t stack_size = (size_t)stack_high - (size_t)stack_low;
	stack_size = (stack_size > STACK_SIZE) ? stack_size : STACK_SIZE;
	new_stack_low = stack_high - stack_size - SS_OFFSET;

	unsigned char vec;
	if (mincore(new_stack_low, stack_size, &vec) == 0)
		error("shadow stack region has been occupied by others");

    new_stack_low = mmap(new_stack_low, stack_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_stack_low == MAP_FAILED)
        error("failed to allocate stack: %s", strerror(errno));
    //printf("shadow stack created at expected location\n");
    return;
}
#endif
