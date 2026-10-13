/* offsets_0960.h — généré par extract_offsets.py
 * Source       : kdata_dump_0960.bin
 * kdata        : 0xffffffff8e270000
 * kbase        : 0xffffffff8d5d0000
 * kdata-kbase  : 0xca0000
 */
#ifndef OFFSETS_0960_H
#define OFFSETS_0960_H

#include <stdint.h>

/* --- Bases FW 9.60 --- */
#define FW_0960_KDATA_VA           0xffffffff8e270000ULL
#define FW_0960_KBASE_VA           0xffffffff8d5d0000ULL
#define FW_0960_KDATA_KBASE_DELTA  0xca0000ULL

/* --- allproc --- */
#define FW_0960_ALLPROC_VA         0xffffffff9007b9f0ULL
#define FW_0960_ALLPROC_OFF_KBASE  0x2aab9f0ULL
#define FW_0960_ALLPROC_OFF_KDATA  0x1e0b9f0ULL

/* --- sysent --- */
#define FW_0960_SYSENT_VA          0xffffffff8e412650ULL
#define FW_0960_SYSENT_OFF_KBASE   0xe42650ULL
#define FW_0960_SYSENT_OFF_KDATA   0x1a2650ULL
#define FW_0960_SYSENT_N           679U
#define FW_0960_SYSENT_ENTRY_SIZE  0x30ULL
#define FW_0960_SYSENT_SY_CALL_OFF 0x08ULL

/* --- struct proc (validé par dump) --- */
#define FW_0960_PROC_PID_OFF       0x0bcU
#define FW_0960_PROC_VM_SPACE_OFF  0x200U   /* hv-test v89 */
#define FW_0960_PROC_UCRED_OFF     0x040U   /* hv-test v89 */

/* --- struct ucred (validé par dump uid=1000) --- */
#define FW_0960_UCRED_UID_OFF      0x04U
#define FW_0960_UCRED_RUID_OFF     0x08U
#define FW_0960_UCRED_SVUID_OFF    0x0cU
#define FW_0960_UCRED_NGROUPS_OFF  0x10U
#define FW_0960_UCRED_RGID_OFF     0x14U
#define FW_0960_UCRED_SVGID_OFF    0x18U
#define FW_0960_UCRED_AUTHID_OFF   0x58U
#define FW_0960_UCRED_CAPS0_OFF    0x60U
#define FW_0960_UCRED_CAPS1_OFF    0x68U
#define FW_0960_UCRED_ATTRS0_OFF   0x80U

/* --- security_flags --- */
#define FW_0960_OFF_SECURITY_FLAGS 0x1a13064ULL

/* --- Constantes jailbreak --- */
#define FW_0960_JAIL_AUTHID        0x4800000000000007ULL
#define FW_0960_JAIL_CAPS          0xFFFFFFFFFFFFFFFFULL
#define FW_0960_JAIL_ATTRS         0xFFFFFFFFFFFFFFFFULL

/* --- Compat hv-test v89 --- */
/* Ces macros matchent celles utilisées dans hv-test v89
 * pour faciliter le portage vers le payload Linux. */
#define OFF_ALLPROC                FW_0960_ALLPROC_OFF_KBASE
#define PROC_VM_SPACE_OFF          FW_0960_PROC_VM_SPACE_OFF
#define PROC_PID_OFF               FW_0960_PROC_PID_OFF

#endif /* OFFSETS_0960_H */
