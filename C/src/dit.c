#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#elif defined(__linux__)
#define _GNU_SOURCE
#endif

#include "dit.h"

#include <stdint.h>

#if defined(__aarch64__) && !defined(FALCON_NO_DIT) && (defined(__APPLE__) || defined(__linux__))
#define FALCON_HAVE_DIT 1
#if defined(__APPLE__)
#include <sys/sysctl.h>
#else
#include <sys/auxv.h>
#endif
#endif

#ifdef FALCON_HAVE_DIT

/* Instruktionen als feste Kodierung, damit kein -march nötig ist:
 * msr dit, #1 = 0xd503415f; msr dit, #0 = 0xd503405f; sb = 0xd50330ff;
 * DIT lesen über den allgemeinen Namen des Systemregisters S3_3_C4_C2_5 (Bit 24). */

static int feature(const char *name, unsigned long hwcap_bit)
{
#if defined(__APPLE__)
    (void)hwcap_bit;
    int value = 0;
    size_t size = sizeof value;
    if (sysctlbyname(name, &value, &size, NULL, 0) != 0) {
        return 0;
    }
    return value != 0;
#else
    (void)name;
    return (getauxval(AT_HWCAP) & hwcap_bit) != 0;
#endif
}

/* -1: noch nicht geprüft. Gleichzeitiges erstes Prüfen in mehreren Threads ergibt denselben Wert. */
static volatile int have_dit = -1, have_sb = -1;

int falcon_dit_supported(void)
{
    if (have_dit < 0) {
        have_dit = feature("hw.optional.arm.FEAT_DIT", 1ul << 24); /* HWCAP_DIT */
        have_sb = feature("hw.optional.arm.FEAT_SB", 1ul << 29);   /* HWCAP_SB */
    }
    return have_dit;
}

int falcon_dit_active(void)
{
    if (!falcon_dit_supported()) {
        return 0;
    }
    uint64_t v;
    __asm__ __volatile__("mrs %0, S3_3_C4_C2_5" : "=r"(v));
    return (int)((v >> 24) & 1u);
}

static void speculation_barrier(void)
{
    if (have_sb) {
        __asm__ __volatile__(".inst 0xd50330ff" ::: "memory");
    } else {
        __asm__ __volatile__("dsb nsh\n\tisb sy" ::: "memory");
    }
}

int falcon_dit_enable(void)
{
    if (!falcon_dit_supported()) {
        return 0;
    }
    int previous = falcon_dit_active();
    __asm__ __volatile__(".inst 0xd503415f" ::: "memory");
    speculation_barrier();
    return previous;
}

void falcon_dit_restore(int previous)
{
    if (falcon_dit_supported() && !previous) {
        __asm__ __volatile__(".inst 0xd503405f" ::: "memory");
    }
}

#else

int falcon_dit_supported(void)
{
    return 0;
}

int falcon_dit_active(void)
{
    return 0;
}

int falcon_dit_enable(void)
{
    return 0;
}

void falcon_dit_restore(int previous)
{
    (void)previous;
}

#endif
