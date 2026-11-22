#ifndef ELF64_RECOMP_DXBC_MSL_H
#define ELF64_RECOMP_DXBC_MSL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char     semantic[32];
    uint32_t semantic_index;
    uint32_t sys_val;
    uint32_t comp_type; /* 1=uint32, 2=sint32, 3=float32 */
    uint32_t reg;
    uint8_t  mask;
} DxbcSigElem;

typedef struct {
    int         is_pixel; /* 0 = vertex shader, 1 = pixel shader */
    DxbcSigElem inputs[16];
    int         num_inputs;
    DxbcSigElem outputs[16];
    int         num_outputs;
    char       *msl_source; /* heap-allocated MSL source string */
} DxbcTranslated;

/* Translate a DXBC container (SM4/SM5 VS or PS) into Apple Metal Shading Language.
 * Returns 0 on success (caller frees out->msl_source), non-zero on error. */
int dxbc_to_msl(const void *bytecode, size_t size, DxbcTranslated *out);

#endif /* ELF64_RECOMP_DXBC_MSL_H */
