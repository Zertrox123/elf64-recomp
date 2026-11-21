#include "dxbc_msl.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} StrBuf;

static void sb_appendf(StrBuf *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char tmp[1024];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (sb->len + (size_t)n + 1 > sb->cap) {
        size_t ncap = sb->cap ? sb->cap * 2 : 4096;
        while (ncap < sb->len + (size_t)n + 1) ncap *= 2;
        sb->data = (char *)realloc(sb->data, ncap);
        sb->cap = ncap;
    }
    memcpy(sb->data + sb->len, tmp, (size_t)n);
    sb->len += (size_t)n;
    sb->data[sb->len] = '\0';
}

static uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static void parse_sig(const uint8_t *payload, uint32_t sz, DxbcSigElem *arr, int *out_n) {
    *out_n = 0;
    if (sz < 8) return;
    uint32_t count = rd32(payload);
    if (count > 16) count = 16;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t off = 8 + i * 24;
        if (off + 24 > sz) break;
        uint32_t name_off = rd32(payload + off + 0);
        arr[i].semantic_index = rd32(payload + off + 4);
        arr[i].sys_val = rd32(payload + off + 8);
        arr[i].reg = rd32(payload + off + 16);
        arr[i].mask = payload[off + 20];
        if (name_off < sz) {
            snprintf(arr[i].semantic, sizeof(arr[i].semantic), "%s", (const char *)(payload + name_off));
        } else {
            arr[i].semantic[0] = '\0';
        }
        (*out_n)++;
    }
}

typedef struct {
    uint32_t reg_type;
    uint32_t idx[2];
    uint32_t idx_dim;
    uint32_t sel_mode;
    uint32_t mask;
    uint32_t swizzle;
    uint32_t select1;
    uint32_t mod; /* 1=neg, 2=abs, 3=abs_neg */
    float    imm[4];
    int      imm_count;
} DxbcOp;

static size_t decode_operand(const uint32_t *toks, size_t pos, size_t end, DxbcOp *op) {
    memset(op, 0, sizeof(*op));
    if (pos >= end) return pos;
    uint32_t t = toks[pos++];
    uint32_t num_comps = t & 3U;
    op->sel_mode = (t >> 2) & 3U;
    if (op->sel_mode == 0)      op->mask = (t >> 4) & 0xFU;
    else if (op->sel_mode == 1) op->swizzle = (t >> 4) & 0xFFU;
    else if (op->sel_mode == 2) op->select1 = (t >> 4) & 3U;
    op->reg_type = (t >> 12) & 0xFFU;
    op->idx_dim = (t >> 20) & 3U;
    int extended = (int)((t >> 31) & 1U);
    if (extended && pos < end) {
        uint32_t ext = toks[pos++];
        if ((ext & 0x3FU) == 1U) {
            op->mod = (ext >> 6) & 3U;
        }
    }
    for (uint32_t d = 0; d < op->idx_dim && d < 2; d++) {
        uint32_t rep = (t >> (22 + d * 3)) & 7U;
        if (rep == 0 && pos < end) {
            op->idx[d] = toks[pos++];
        }
    }
    if (op->reg_type == 4) { /* IMM32 */
        op->imm_count = (num_comps == 2) ? 4 : 1;
        for (int i = 0; i < op->imm_count && pos < end; i++) {
            uint32_t u = toks[pos++];
            memcpy(&op->imm[i], &u, 4);
        }
    }
    return pos;
}

static void fmt_swizzle(const DxbcOp *op, char out[8]) {
    static const char ch[4] = {'x', 'y', 'z', 'w'};
    if (op->sel_mode == 1) {
        out[0] = ch[(op->swizzle >> 0) & 3];
        out[1] = ch[(op->swizzle >> 2) & 3];
        out[2] = ch[(op->swizzle >> 4) & 3];
        out[3] = ch[(op->swizzle >> 6) & 3];
        out[4] = '\0';
    } else if (op->sel_mode == 2) {
        char c = ch[op->select1 & 3];
        out[0] = c; out[1] = c; out[2] = c; out[3] = c; out[4] = '\0';
    } else {
        strcpy(out, "xyzw");
    }
}

static void fmt_mask(uint32_t mask, char out[8]) {
    static const char ch[4] = {'x', 'y', 'z', 'w'};
    int n = 0;
    for (int i = 0; i < 4; i++) {
        if (mask & (1U << i)) out[n++] = ch[i];
    }
    if (n == 0) { strcpy(out, "xyzw"); return; }
    out[n] = '\0';
}

static void fmt_src(const DxbcOp *op, uint32_t dst_mask, char *out, size_t cap) {
    char base[128];
    if (op->reg_type == 0) {
        snprintf(base, sizeof(base), "r%u", op->idx[0]);
    } else if (op->reg_type == 1) {
        snprintf(base, sizeof(base), "v%u", op->idx[0]);
    } else if (op->reg_type == 8) {
        snprintf(base, sizeof(base), "cb%u[%u]", op->idx[0], op->idx[1]);
    } else if (op->reg_type == 4) {
        if (op->imm_count == 1) {
            snprintf(base, sizeof(base), "float4(%g, %g, %g, %g)",
                     op->imm[0], op->imm[0], op->imm[0], op->imm[0]);
        } else {
            snprintf(base, sizeof(base), "float4(%g, %g, %g, %g)",
                     op->imm[0], op->imm[1], op->imm[2], op->imm[3]);
        }
    } else {
        snprintf(base, sizeof(base), "float4(0.0)");
    }

    char sw[8];
    fmt_swizzle(op, sw);
    /* Project swizzle onto active destination write mask lanes. */
    char proj[8];
    int n = 0;
    for (int i = 0; i < 4; i++) {
        if (dst_mask & (1U << i)) proj[n++] = sw[i];
    }
    if (n == 0) { strcpy(proj, sw); } else { proj[n] = '\0'; }

    char raw[160];
    snprintf(raw, sizeof(raw), "(%s).%s", base, proj);
    if (op->mod == 1)      snprintf(out, cap, "(-%s)", raw);
    else if (op->mod == 2) snprintf(out, cap, "abs(%s)", raw);
    else if (op->mod == 3) snprintf(out, cap, "(-abs(%s))", raw);
    else                   snprintf(out, cap, "%s", raw);
}

static void fmt_dst(const DxbcOp *op, char *out, size_t cap, char mask_str[8]) {
    uint32_t m = op->mask ? op->mask : 0xF;
    fmt_mask(m, mask_str);
    if (op->reg_type == 0)      snprintf(out, cap, "r%u.%s", op->idx[0], mask_str);
    else if (op->reg_type == 2) snprintf(out, cap, "o%u.%s", op->idx[0], mask_str);
    else                        snprintf(out, cap, "r0.%s", mask_str);
}

static int mask_lane_count(uint32_t m) {
    int c = 0;
    for (int i = 0; i < 4; i++) if (m & (1U << i)) c++;
    return c ? c : 4;
}

int dxbc_to_msl(const void *bytecode, size_t size, DxbcTranslated *out) {
    memset(out, 0, sizeof(*out));
    const uint8_t *b = (const uint8_t *)bytecode;
    if (!b || size < 32 || memcmp(b, "DXBC", 4) != 0) return -1;

    uint32_t nchunks = rd32(b + 28);
    const uint8_t *shdr = NULL;
    uint32_t shdr_sz = 0;

    for (uint32_t i = 0; i < nchunks; i++) {
        if (32 + (i + 1) * 4 > size) return -1;
        uint32_t coff = rd32(b + 32 + i * 4);
        if (coff + 8 > size) return -1;
        uint32_t csz = rd32(b + coff + 4);
        if (coff + 8 + csz > size) return -1;
        const uint8_t *payload = b + coff + 8;
        if (memcmp(b + coff, "ISGN", 4) == 0) {
            parse_sig(payload, csz, out->inputs, &out->num_inputs);
        } else if (memcmp(b + coff, "OSGN", 4) == 0) {
            parse_sig(payload, csz, out->outputs, &out->num_outputs);
        } else if (memcmp(b + coff, "SHDR", 4) == 0 || memcmp(b + coff, "SHEX", 4) == 0) {
            shdr = payload;
            shdr_sz = csz;
        }
    }
    if (!shdr || shdr_sz < 8) return -2;

    size_t ntoks = shdr_sz / 4;
    const uint32_t *toks = (const uint32_t *)shdr;
    uint32_t stype = (toks[0] >> 16) & 0xFFFFU;
    out->is_pixel = (stype == 0) ? 1 : 0;

    /* Pre-scan for DCL_TEMPS and constant buffers */
    uint32_t num_temps = 4;
    int has_cb0 = 0;
    for (size_t p = 2; p < ntoks; ) {
        uint32_t tok = toks[p];
        uint32_t op = tok & 0x7FFU;
        uint32_t len = (tok >> 24) & 0x7FU;
        if (len == 0 || p + len > ntoks) break;
        if (op == 104 && len >= 2) num_temps = toks[p + 1]; /* DCL_TEMPS */
        if (op == 89) has_cb0 = 1; /* DCL_CONSTANT_BUFFER */
        p += len;
    }

    StrBuf sb = {0};
    sb_appendf(&sb, "#include <metal_stdlib>\nusing namespace metal;\n\n");

    if (!out->is_pixel) {
        sb_appendf(&sb, "struct VSIn {\n");
        for (int i = 0; i < out->num_inputs; i++) {
            sb_appendf(&sb, "    float4 v%u [[attribute(%u)]];\n", out->inputs[i].reg, out->inputs[i].reg);
        }
        sb_appendf(&sb, "};\n\nstruct VSOut {\n");
        for (int i = 0; i < out->num_outputs; i++) {
            if (out->outputs[i].sys_val == 1 || strcasecmp(out->outputs[i].semantic, "SV_POSITION") == 0) {
                sb_appendf(&sb, "    float4 o%u [[position]];\n", out->outputs[i].reg);
            } else {
                sb_appendf(&sb, "    float4 o%u [[user(loc%u)]];\n", out->outputs[i].reg, out->outputs[i].reg);
            }
        }
        sb_appendf(&sb, "};\n\nvertex VSOut vs_main(VSIn in [[stage_in]]");
        if (has_cb0) sb_appendf(&sb, ", constant float4 *cb0 [[buffer(16)]]");
        sb_appendf(&sb, ") {\n");
        for (int i = 0; i < out->num_inputs; i++) {
            sb_appendf(&sb, "    float4 v%u = in.v%u;\n", out->inputs[i].reg, out->inputs[i].reg);
        }
        for (int i = 0; i < out->num_outputs; i++) {
            sb_appendf(&sb, "    float4 o%u = float4(0.0);\n", out->outputs[i].reg);
        }
    } else {
        sb_appendf(&sb, "struct PSIn {\n");
        for (int i = 0; i < out->num_inputs; i++) {
            if (out->inputs[i].sys_val == 1 || strcasecmp(out->inputs[i].semantic, "SV_POSITION") == 0) {
                sb_appendf(&sb, "    float4 v%u [[position]];\n", out->inputs[i].reg);
            } else {
                sb_appendf(&sb, "    float4 v%u [[user(loc%u)]];\n", out->inputs[i].reg, out->inputs[i].reg);
            }
        }
        sb_appendf(&sb, "};\n\nfragment float4 fs_main(PSIn in [[stage_in]]");
        if (has_cb0) sb_appendf(&sb, ", constant float4 *cb0 [[buffer(16)]]");
        sb_appendf(&sb, ") {\n");
        for (int i = 0; i < out->num_inputs; i++) {
            sb_appendf(&sb, "    float4 v%u = in.v%u;\n", out->inputs[i].reg, out->inputs[i].reg);
        }
        sb_appendf(&sb, "    float4 o0 = float4(0.0);\n");
    }

    for (uint32_t t = 0; t < num_temps; t++) {
        sb_appendf(&sb, "    float4 r%u = float4(0.0);\n", t);
    }

    /* Decode SM4/SM5 instruction stream */
    for (size_t p = 2; p < ntoks; ) {
        uint32_t tok = toks[p];
        uint32_t opc = tok & 0x7FFU;
        uint32_t len = (tok >> 24) & 0x7FU;
        if (len == 0 || p + len > ntoks) break;
        size_t end = p + len;
        size_t cur = p + 1;
        while ((tok & 0x80000000U) && cur < end) {
            tok = toks[cur++];
        }

        if (opc >= 88) { p = end; continue; } /* Declarations */
        if (opc == 62) { /* RET */
            if (!out->is_pixel) {
                sb_appendf(&sb, "    VSOut _out;\n");
                for (int i = 0; i < out->num_outputs; i++) {
                    sb_appendf(&sb, "    _out.o%u = o%u;\n", out->outputs[i].reg, out->outputs[i].reg);
                }
                sb_appendf(&sb, "    return _out;\n");
            } else {
                sb_appendf(&sb, "    return o0;\n");
            }
            p = end;
            continue;
        }

        DxbcOp d, s0, s1, s2;
        char ds[64], dm[8], a0[192], a1[192], a2[192];
        if (opc == 54) { /* MOV */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            sb_appendf(&sb, "    %s = %s;\n", ds, a0);
        } else if (opc == 0 || opc == 56 || opc == 14) { /* ADD / MUL / DIV */
            const char *sym = (opc == 0) ? "+" : (opc == 56 ? "*" : "/");
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            sb_appendf(&sb, "    %s = (%s) %s (%s);\n", ds, a0, sym, a1);
        } else if (opc == 50) { /* MAD */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            cur = decode_operand(toks, cur, end, &s2);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            fmt_src(&s2, m, a2, sizeof(a2));
            sb_appendf(&sb, "    %s = fma(%s, %s, %s);\n", ds, a0, a1, a2);
        } else if (opc == 15 || opc == 16 || opc == 17) { /* DP2 / DP3 / DP4 */
            uint32_t dp_mask = (opc == 15) ? 0x3 : (opc == 16 ? 0x7 : 0xF);
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, dp_mask, a0, sizeof(a0));
            fmt_src(&s1, dp_mask, a1, sizeof(a1));
            int nc = mask_lane_count(m);
            if (nc == 1) sb_appendf(&sb, "    %s = dot(%s, %s);\n", ds, a0, a1);
            else         sb_appendf(&sb, "    %s = float%d(dot(%s, %s));\n", ds, nc, a0, a1);
        } else if (opc == 51 || opc == 52) { /* MIN / MAX */
            const char *fn = (opc == 51) ? "min" : "max";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            sb_appendf(&sb, "    %s = %s(%s, %s);\n", ds, fn, a0, a1);
        } else if (opc == 68 || opc == 72) { /* RSQ / SQRT */
            const char *fn = (opc == 68) ? "rsqrt" : "sqrt";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            sb_appendf(&sb, "    %s = %s(%s);\n", ds, fn, a0);
        }
        p = end;
    }

    sb_appendf(&sb, "}\n");
    out->msl_source = sb.data;
    return 0;
}
