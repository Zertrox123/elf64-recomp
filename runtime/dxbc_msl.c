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
        arr[i].comp_type = rd32(payload + off + 12);
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
    int      rel_dim[2];
    uint32_t rel_reg[2];
    uint32_t rel_comp[2];
    uint32_t sel_mode;
    uint32_t mask;
    uint32_t swizzle;
    uint32_t select1;
    uint32_t mod; /* 1=neg, 2=abs, 3=abs_neg */
    uint32_t imm_u[4];
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
    while (extended && pos < end) {
        uint32_t ext = toks[pos++];
        if ((ext & 0x3FU) == 1U) op->mod = (ext >> 6) & 3U;
        extended = (int)((ext >> 31) & 1U);
    }
    for (uint32_t d = 0; d < op->idx_dim && d < 2; d++) {
        uint32_t rep = (t >> (22 + d * 3)) & 7U;
        if (rep == 0 && pos < end) {
            op->idx[d] = toks[pos++];
        } else if (rep == 1 && pos + 1 < end) {
            op->idx[d] = toks[pos++]; pos++;
        } else if (rep == 2 && pos < end) {
            DxbcOp sub;
            pos = decode_operand(toks, pos, end, &sub);
            op->rel_dim[d] = 1;
            op->rel_reg[d] = sub.idx[0];
            op->rel_comp[d] = (sub.sel_mode == 2) ? sub.select1 : (sub.swizzle & 3U);
        } else if (rep == 3 && pos < end) {
            op->idx[d] = toks[pos++];
            DxbcOp sub;
            pos = decode_operand(toks, pos, end, &sub);
            op->rel_dim[d] = 1;
            op->rel_reg[d] = sub.idx[0];
            op->rel_comp[d] = (sub.sel_mode == 2) ? sub.select1 : (sub.swizzle & 3U);
        }
    }
    if (op->reg_type == 4) { /* IMM32 */
        op->imm_count = (num_comps == 2) ? 4 : 1;
        for (int i = 0; i < op->imm_count && pos < end; i++) {
            uint32_t u = toks[pos++];
            op->imm_u[i] = u;
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

static void fmt_sem_attr(const DxbcSigElem *e, char *out, size_t cap) {
    char clean[32];
    size_t j = 0;
    for (size_t i = 0; e->semantic[i] && j + 1 < sizeof(clean); i++) {
        char c = e->semantic[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') clean[j++] = c;
    }
    clean[j] = '\0';
    if (!clean[0]) snprintf(out, cap, "loc%u", e->reg & 31U);
    else           snprintf(out, cap, "sem_%s_%u", clean, e->semantic_index);
}

static void fmt_src(const DxbcOp *op, uint32_t dst_mask, char *out, size_t cap) {
    static const char ch[4] = {'x', 'y', 'z', 'w'};
    char base[192];
    if (op->reg_type == 0) {
        snprintf(base, sizeof(base), "r%u", op->idx[0]);
    } else if (op->reg_type == 1) {
        snprintf(base, sizeof(base), "v%u", op->idx[0]);
    } else if (op->reg_type == 8) {
        if (op->rel_dim[1]) {
            snprintf(base, sizeof(base), "cb%u[(uint)(as_type<int>(r%u.%c) + %u)]",
                     op->idx[0], op->rel_reg[1], ch[op->rel_comp[1] & 3U], op->idx[1]);
        } else {
            snprintf(base, sizeof(base), "cb%u[%u]", op->idx[0], op->idx[1]);
        }
    } else if (op->reg_type == 4) {
        if (op->imm_count == 1) {
            snprintf(base, sizeof(base), "float4(as_type<float>(0x%08Xu))", op->imm_u[0]);
        } else {
            snprintf(base, sizeof(base),
                     "float4(as_type<float>(0x%08Xu),as_type<float>(0x%08Xu),as_type<float>(0x%08Xu),as_type<float>(0x%08Xu))",
                     op->imm_u[0], op->imm_u[1], op->imm_u[2], op->imm_u[3]);
        }
    } else {
        if (getenv("ELF64_D3D11_TRACE")) {
            static uint64_t seen_rt = 0;
            if (op->reg_type < 64 && !(seen_rt & (1ULL << op->reg_type))) {
                seen_rt |= (1ULL << op->reg_type);
                fprintf(stderr, "[dxbc] unhandled src reg_type=%u idx0=%u idx1=%u\n", op->reg_type, op->idx[0], op->idx[1]);
            }
        }
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

    /* Pre-scan for DCL_TEMPS, constant buffers, textures (with dim), and samplers */
    uint32_t num_temps = 4;
    uint32_t cb_mask = 0, tex_mask = 0, samp_mask = 0;
    uint8_t  tex_dim[16] = {0}; /* 2=2D, 3=3D, 4=Cube */
    for (size_t p = 2; p < ntoks; ) {
        uint32_t tok0 = toks[p];
        uint32_t tok = tok0;
        uint32_t op = tok0 & 0x7FFU;
        uint32_t len = (tok0 >> 24) & 0x7FU;
        if (len == 0 || p + len > ntoks) break;
        size_t end = p + len, cur = p + 1;
        while ((tok & 0x80000000U) && cur < end) tok = toks[cur++];
        if (op == 104 && cur < end) {
            if (toks[cur] > num_temps) num_temps = toks[cur];
        } else if (op == 89 && cur < end) {
            DxbcOp cb;
            decode_operand(toks, cur, end, &cb);
            if (cb.idx[0] < 14) cb_mask |= (1U << cb.idx[0]);
        } else if (op == 88 && cur < end) {
            DxbcOp tx;
            decode_operand(toks, cur, end, &tx);
            if (tx.idx[0] < 16) {
                tex_mask |= (1U << tx.idx[0]);
                /* D3D10_SB_RESOURCE_DIMENSION: 3=TEX2D, 5=TEX3D, 6=TEXCUBE */
                uint32_t dim = (tok0 >> 11) & 0x1FU;
                tex_dim[tx.idx[0]] = (dim == 6) ? 4 : ((dim == 5) ? 3 : 2);
            }
        } else if (op == 90 && cur < end) {
            DxbcOp sm;
            decode_operand(toks, cur, end, &sm);
            if (sm.idx[0] < 16) samp_mask |= (1U << sm.idx[0]);
        }
        p = end;
    }

    StrBuf sb = {0};
    sb_appendf(&sb, "#include <metal_stdlib>\nusing namespace metal;\n\n");

    int has_vid = 0, has_iid = 0, clip_reg = -1, has_ff = 0, ps_rt_count = 0;
    if (!out->is_pixel) {
        int n_stage_in = 0;
        uint32_t seen_in = 0, seen_out = 0;
        for (int i = 0; i < out->num_inputs; i++) {
            if (out->inputs[i].sys_val == 6 || strcasecmp(out->inputs[i].semantic, "SV_VERTEXID") == 0) {
                has_vid = 1;
            } else if (out->inputs[i].sys_val == 8 || strcasecmp(out->inputs[i].semantic, "SV_INSTANCEID") == 0) {
                has_iid = 1;
            } else if (!(seen_in & (1U << (out->inputs[i].reg & 31U)))) {
                seen_in |= (1U << (out->inputs[i].reg & 31U));
                n_stage_in++;
            }
        }
        if (n_stage_in > 0) {
            seen_in = 0;
            sb_appendf(&sb, "struct VSIn {\n");
            for (int i = 0; i < out->num_inputs; i++) {
                if (out->inputs[i].sys_val == 6 || strcasecmp(out->inputs[i].semantic, "SV_VERTEXID") == 0 ||
                    out->inputs[i].sys_val == 8 || strcasecmp(out->inputs[i].semantic, "SV_INSTANCEID") == 0) continue;
                uint32_t r = out->inputs[i].reg & 31U;
                if (seen_in & (1U << r)) continue;
                seen_in |= (1U << r);
                const char *vt = (out->inputs[i].comp_type == 1) ? "uint4" : (out->inputs[i].comp_type == 2 ? "int4" : "float4");
                sb_appendf(&sb, "    %s v%u [[attribute(%u)]];\n", vt, r, r);
            }
            sb_appendf(&sb, "};\n\n");
        }
        sb_appendf(&sb, "struct VSOut {\n");
        int has_pos = 0;
        seen_out = 0;
        for (int i = 0; i < out->num_outputs; i++) {
            uint32_t r = out->outputs[i].reg & 31U;
            if (seen_out & (1U << r)) continue;
            seen_out |= (1U << r);
            if (out->outputs[i].sys_val == 1 || strcasecmp(out->outputs[i].semantic, "SV_POSITION") == 0) {
                sb_appendf(&sb, "    float4 o%u [[position]];\n", r);
                has_pos = 1;
            } else if (out->outputs[i].sys_val == 2 || strncasecmp(out->outputs[i].semantic, "SV_CLIPDISTANCE", 15) == 0) {
                if (clip_reg < 0) {
                    clip_reg = (int)r;
                    sb_appendf(&sb, "    float _clip [[clip_distance]];\n");
                }
                char sattr[48];
                fmt_sem_attr(&out->outputs[i], sattr, sizeof(sattr));
                sb_appendf(&sb, "    float4 o%u [[user(%s)]];\n", r, sattr);
            } else {
                char sattr[48];
                fmt_sem_attr(&out->outputs[i], sattr, sizeof(sattr));
                sb_appendf(&sb, "    float4 o%u [[user(%s)]];\n", r, sattr);
            }
        }
        if (!has_pos) sb_appendf(&sb, "    float4 _pos [[position]];\n");
        sb_appendf(&sb, "};\n\nvertex VSOut vs_main(");
        int first_arg = 1;
        if (n_stage_in > 0) { sb_appendf(&sb, "VSIn in [[stage_in]]"); first_arg = 0; }
        if (has_vid) { sb_appendf(&sb, "%suint _vid [[vertex_id]]", first_arg ? "" : ", "); first_arg = 0; }
        if (has_iid) { sb_appendf(&sb, "%suint _iid [[instance_id]]", first_arg ? "" : ", "); first_arg = 0; }
        for (uint32_t k = 0; k < 14; k++) {
            if (cb_mask & (1U << k)) { sb_appendf(&sb, "%sconstant float4 *cb%u [[buffer(%u)]]", first_arg ? "" : ", ", k, 16 + k); first_arg = 0; }
        }
        for (uint32_t k = 0; k < 16; k++) {
            if (tex_mask & (1U << k)) {
                const char *tt = (tex_dim[k] == 4) ? "texturecube<float>" : (tex_dim[k] == 3 ? "texture3d<float>" : "texture2d<float>");
                sb_appendf(&sb, "%s%s t%u [[texture(%u)]]", first_arg ? "" : ", ", tt, k, k);
                first_arg = 0;
            }
        }
        for (uint32_t k = 0; k < 16; k++) {
            if (samp_mask & (1U << k)) { sb_appendf(&sb, "%ssampler s%u [[sampler(%u)]]", first_arg ? "" : ", ", k, k); first_arg = 0; }
        }
        sb_appendf(&sb, ") {\n");
        seen_in = 0;
        for (int i = 0; i < out->num_inputs; i++) {
            uint32_t r = out->inputs[i].reg & 31U;
            if (seen_in & (1U << r)) continue;
            seen_in |= (1U << r);
            if (out->inputs[i].sys_val == 6 || strcasecmp(out->inputs[i].semantic, "SV_VERTEXID") == 0) {
                sb_appendf(&sb, "    float4 v%u = as_type<float4>(uint4(_vid, 0u, 0u, 0u));\n", r);
            } else if (out->inputs[i].sys_val == 8 || strcasecmp(out->inputs[i].semantic, "SV_INSTANCEID") == 0) {
                sb_appendf(&sb, "    float4 v%u = as_type<float4>(uint4(_iid, 0u, 0u, 0u));\n", r);
            } else if (out->inputs[i].comp_type == 1 || out->inputs[i].comp_type == 2) {
                sb_appendf(&sb, "    float4 v%u = as_type<float4>(in.v%u);\n", r, r);
            } else {
                sb_appendf(&sb, "    float4 v%u = in.v%u;\n", r, r);
            }
        }
        seen_out = 0;
        for (int i = 0; i < out->num_outputs; i++) {
            uint32_t r = out->outputs[i].reg & 31U;
            if (seen_out & (1U << r)) continue;
            seen_out |= (1U << r);
            sb_appendf(&sb, "    float4 o%u = float4(0.0);\n", r);
        }
    } else {
        uint32_t seen_in = 0, seen_out = 0;
        int n_ps_in = 0;
        for (int i = 0; i < out->num_inputs; i++) {
            if (out->inputs[i].sys_val == 9 || strcasecmp(out->inputs[i].semantic, "SV_ISFRONTFACE") == 0) {
                has_ff = 1;
                continue;
            }
            uint32_t r = out->inputs[i].reg & 31U;
            if (!(seen_in & (1U << r))) { seen_in |= (1U << r); n_ps_in++; }
        }
        for (int i = 0; i < out->num_outputs; i++) {
            uint32_t r = out->outputs[i].reg & 31U;
            if (r < 4 && (int)(r + 1) > ps_rt_count) ps_rt_count = (int)(r + 1);
        }
        if (ps_rt_count <= 0) ps_rt_count = 1;
        if (n_ps_in > 0) {
            seen_in = 0;
            sb_appendf(&sb, "struct PSIn {\n");
            for (int i = 0; i < out->num_inputs; i++) {
                if (out->inputs[i].sys_val == 9 || strcasecmp(out->inputs[i].semantic, "SV_ISFRONTFACE") == 0) continue;
                uint32_t r = out->inputs[i].reg & 31U;
                if (seen_in & (1U << r)) continue;
                seen_in |= (1U << r);
                if (out->inputs[i].sys_val == 1 || strcasecmp(out->inputs[i].semantic, "SV_POSITION") == 0) {
                    sb_appendf(&sb, "    float4 v%u [[position]];\n", r);
                } else {
                    char sattr[48];
                    fmt_sem_attr(&out->inputs[i], sattr, sizeof(sattr));
                    sb_appendf(&sb, "    float4 v%u [[user(%s)]];\n", r, sattr);
                }
            }
            sb_appendf(&sb, "};\n\n");
        }
        if (ps_rt_count > 1) {
            sb_appendf(&sb, "struct PSOut {\n");
            for (int i = 0; i < ps_rt_count; i++)
                sb_appendf(&sb, "    float4 o%d [[color(%d)]];\n", i, i);
            sb_appendf(&sb, "};\n\nfragment PSOut fs_main(");
        } else {
            sb_appendf(&sb, "fragment float4 fs_main(");
        }
        int first_arg = 1;
        if (n_ps_in > 0) { sb_appendf(&sb, "PSIn in [[stage_in]]"); first_arg = 0; }
        if (has_ff) { sb_appendf(&sb, "%sbool _ff [[front_facing]]", first_arg ? "" : ", "); first_arg = 0; }
        for (uint32_t k = 0; k < 14; k++) {
            if (cb_mask & (1U << k)) { sb_appendf(&sb, "%sconstant float4 *cb%u [[buffer(%u)]]", first_arg ? "" : ", ", k, 16 + k); first_arg = 0; }
        }
        for (uint32_t k = 0; k < 16; k++) {
            if (tex_mask & (1U << k)) {
                const char *tt = (tex_dim[k] == 4) ? "texturecube<float>" : (tex_dim[k] == 3 ? "texture3d<float>" : "texture2d<float>");
                sb_appendf(&sb, "%s%s t%u [[texture(%u)]]", first_arg ? "" : ", ", tt, k, k);
                first_arg = 0;
            }
        }
        for (uint32_t k = 0; k < 16; k++) {
            if (samp_mask & (1U << k)) { sb_appendf(&sb, "%ssampler s%u [[sampler(%u)]]", first_arg ? "" : ", ", k, k); first_arg = 0; }
        }
        sb_appendf(&sb, ") {\n");
        seen_in = 0;
        for (int i = 0; i < out->num_inputs; i++) {
            uint32_t r = out->inputs[i].reg & 31U;
            if (seen_in & (1U << r)) continue;
            seen_in |= (1U << r);
            if (out->inputs[i].sys_val == 9 || strcasecmp(out->inputs[i].semantic, "SV_ISFRONTFACE") == 0) {
                sb_appendf(&sb, "    float4 v%u = as_type<float4>(uint4(_ff ? 0xFFFFFFFFu : 0u, 0u, 0u, 0u));\n", r);
            } else {
                sb_appendf(&sb, "    float4 v%u = in.v%u;\n", r, r);
            }
        }
        sb_appendf(&sb, "    float4 o0 = float4(0.0);\n");
        seen_out = 1U;
        for (int i = 0; i < out->num_outputs; i++) {
            uint32_t r = out->outputs[i].reg & 31U;
            if (seen_out & (1U << r)) continue;
            seen_out |= (1U << r);
            sb_appendf(&sb, "    float4 o%u = float4(0.0);\n", r);
        }
        for (int i = 0; i < ps_rt_count; i++) {
            if (seen_out & (1U << i)) continue;
            seen_out |= (1U << i);
            sb_appendf(&sb, "    float4 o%d = float4(0.0);\n", i);
        }
    }

    for (uint32_t t = 0; t < num_temps; t++) {
        sb_appendf(&sb, "    float4 r%u = float4(0.0);\n", t);
    }

    /* Decode SM4/SM5 instruction stream */
    for (size_t p = 2; p < ntoks; ) {
        uint32_t tok0 = toks[p];
        uint32_t tok = tok0;
        uint32_t opc = tok0 & 0x7FFU;
        uint32_t sat = (tok0 >> 13) & 1U;
        uint32_t len = (tok0 >> 24) & 0x7FU;
        if (len == 0 || p + len > ntoks) break;
        size_t end = p + len;
        size_t cur = p + 1;
        while ((tok & 0x80000000U) && cur < end) {
            tok = toks[cur++];
        }

        if (opc >= 88 && opc != 128 && opc != 168 && opc != 169) { p = end; continue; } /* Declarations */
        if (opc == 62) { /* RET */
            if (!out->is_pixel) {
                uint32_t seen_out = 0;
                sb_appendf(&sb, "    VSOut _out;\n");
                for (int i = 0; i < out->num_outputs; i++) {
                    uint32_t r = out->outputs[i].reg & 31U;
                    if (seen_out & (1U << r)) continue;
                    seen_out |= (1U << r);
                    sb_appendf(&sb, "    _out.o%u = o%u;\n", r, r);
                }
                if (clip_reg >= 0) sb_appendf(&sb, "    _out._clip = o%d.x;\n", clip_reg);
                sb_appendf(&sb, "    return _out;\n");
            } else if (ps_rt_count > 1) {
                sb_appendf(&sb, "    PSOut _pout;\n");
                for (int i = 0; i < ps_rt_count; i++)
                    sb_appendf(&sb, "    _pout.o%d = o%d;\n", i, i);
                sb_appendf(&sb, "    return _pout;\n");
            } else {
                sb_appendf(&sb, "    return o0;\n");
            }
            p = end;
            continue;
        }

        DxbcOp d, s0, s1, s2;
        char ds[64], dm[8], a0[256], a1[256], a2[256];
        int wrote_dst = 0;
        if (opc == 54) { /* MOV */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            sb_appendf(&sb, "    %s = %s;\n", ds, a0);
            wrote_dst = 1;
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
            wrote_dst = 1;
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
            wrote_dst = 1;
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
            wrote_dst = 1;
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
            wrote_dst = 1;
        } else if (opc == 68 || opc == 75 || opc == 26 || opc == 25 || opc == 47 ||
                   opc == 64 || opc == 65 || opc == 66 || opc == 67 ||
                   opc == 11 || opc == 12 || opc == 168 || opc == 169) { /* RSQ/SQRT/FRC/EXP/LOG/ROUND/DERIV */
            const char *fn =
                (opc == 68) ? "rsqrt" : (opc == 75 ? "sqrt" : (opc == 26 ? "fract" :
                (opc == 25 ? "exp2" : (opc == 47 ? "log2" :
                (opc == 64 ? "rint" : (opc == 65 ? "floor" : (opc == 66 ? "ceil" :
                (opc == 67 ? "trunc" : ((opc == 11 || opc == 168) ? "dfdx" : "dfdy")))))))));
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            sb_appendf(&sb, "    %s = %s(%s);\n", ds, fn, a0);
            wrote_dst = 1;
        } else if (opc == 128) { /* RCP */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            sb_appendf(&sb, "    %s = (1.0 / (%s));\n", ds, a0);
            wrote_dst = 1;
        } else if (opc == 77) { /* SINCOS */
            DxbcOp dcos;
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &dcos);
            cur = decode_operand(toks, cur, end, &s0);
            if (d.reg_type != 13) { /* not NULL */
                uint32_t m = d.mask ? d.mask : 0xF;
                fmt_dst(&d, ds, sizeof(ds), dm);
                fmt_src(&s0, m, a0, sizeof(a0));
                sb_appendf(&sb, "    %s = sin(%s);\n", ds, a0);
            }
            if (dcos.reg_type != 13) {
                uint32_t m = dcos.mask ? dcos.mask : 0xF;
                fmt_dst(&dcos, ds, sizeof(ds), dm);
                fmt_src(&s0, m, a0, sizeof(a0));
                sb_appendf(&sb, "    %s = cos(%s);\n", ds, a0);
            }
        } else if (opc == 55) { /* MOVC */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            cur = decode_operand(toks, cur, end, &s2);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            fmt_src(&s2, m, a2, sizeof(a2));
            if (nc == 1) sb_appendf(&sb, "    %s = (as_type<uint>(%s) != 0u) ? (%s) : (%s);\n", ds, a0, a1, a2);
            else         sb_appendf(&sb, "    %s = select(%s, %s, as_type<uint%d>(%s) != 0u);\n", ds, a2, a1, nc, a0);
            wrote_dst = 1;
        } else if (opc == 24 || opc == 57 || opc == 49 || opc == 29) { /* EQ / NE / LT / GE */
            const char *cmp = (opc == 24) ? "==" : (opc == 57 ? "!=" : (opc == 49 ? "<" : ">="));
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(((%s) %s (%s)) ? 0xFFFFFFFFu : 0u);\n", ds, a0, cmp, a1);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(select(uint%d(0u), uint%d(0xFFFFFFFFu), (%s) %s (%s)));\n", ds, nc, nc, nc, a0, cmp, a1);
        } else if (opc == 32 || opc == 33 || opc == 34 || opc == 39 || opc == 79 || opc == 80) { /* IEQ/IGE/ILT/INE/ULT/UGE */
            const char *cmp = (opc == 32) ? "==" : (opc == 39 ? "!=" : ((opc == 34 || opc == 79) ? "<" : ">="));
            const char *it  = (opc == 79 || opc == 80) ? "uint" : "int";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>((as_type<%s>(%s) %s as_type<%s>(%s)) ? 0xFFFFFFFFu : 0u);\n", ds, it, a0, cmp, it, a1);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(select(uint%d(0u), uint%d(0xFFFFFFFFu), as_type<%s%d>(%s) %s as_type<%s%d>(%s)));\n", ds, nc, nc, nc, it, nc, a0, cmp, it, nc, a1);
        } else if (opc == 1 || opc == 60 || opc == 87 || opc == 30 || opc == 41 || opc == 42 || opc == 85) { /* AND/OR/XOR/IADD/ISHL/ISHR/USHR */
            const char *bop = (opc == 1) ? "&" : (opc == 60 ? "|" : (opc == 87 ? "^" : (opc == 30 ? "+" : (opc == 41 ? "<<" : ">>"))));
            const char *it = (opc == 42) ? "int" : "uint";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(as_type<%s>(%s) %s as_type<%s>(%s));\n", ds, it, a0, bop, it, a1);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(as_type<%s%d>(%s) %s as_type<%s%d>(%s));\n", ds, nc, it, nc, a0, bop, it, nc, a1);
        } else if (opc == 38 || opc == 81) { /* IMUL / UMUL (dhi, dlo, s0, s1) */
            DxbcOp dlo;
            const char *it = (opc == 38) ? "int" : "uint";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &dlo);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            if (dlo.reg_type != 13) {
                uint32_t m = dlo.mask ? dlo.mask : 0xF;
                int nc = mask_lane_count(m);
                fmt_dst(&dlo, ds, sizeof(ds), dm);
                fmt_src(&s0, m, a0, sizeof(a0));
                fmt_src(&s1, m, a1, sizeof(a1));
                if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(as_type<%s>(%s) * as_type<%s>(%s));\n", ds, it, a0, it, a1);
                else         sb_appendf(&sb, "    %s = as_type<float%d>(as_type<%s%d>(%s) * as_type<%s%d>(%s));\n", ds, nc, it, nc, a0, it, nc, a1);
            }
        } else if (opc == 35 || opc == 82) { /* IMAD / UMAD */
            const char *it = (opc == 35) ? "int" : "uint";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            cur = decode_operand(toks, cur, end, &s2);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            fmt_src(&s2, m, a2, sizeof(a2));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(as_type<%s>(%s) * as_type<%s>(%s) + as_type<%s>(%s));\n", ds, it, a0, it, a1, it, a2);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(as_type<%s%d>(%s) * as_type<%s%d>(%s) + as_type<%s%d>(%s));\n", ds, nc, it, nc, a0, it, nc, a1, it, nc, a2);
        } else if (opc == 36 || opc == 37 || opc == 83 || opc == 84) { /* IMIN/IMAX/UMAX/UMIN */
            const char *fn = (opc == 37 || opc == 84) ? "min" : "max";
            const char *it = (opc == 83 || opc == 84) ? "uint" : "int";
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            fmt_src(&s1, m, a1, sizeof(a1));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(%s(as_type<%s>(%s), as_type<%s>(%s)));\n", ds, fn, it, a0, it, a1);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(%s(as_type<%s%d>(%s), as_type<%s%d>(%s)));\n", ds, nc, fn, it, nc, a0, it, nc, a1);
        } else if (opc == 40) { /* INEG */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(-as_type<int>(%s));\n", ds, a0);
            else         sb_appendf(&sb, "    %s = as_type<float%d>(-as_type<int%d>(%s));\n", ds, nc, nc, a0);
        } else if (opc == 43 || opc == 86 || opc == 27 || opc == 28) { /* ITOF / UTOF / FTOI / FTOU */
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            uint32_t m = d.mask ? d.mask : 0xF;
            int nc = mask_lane_count(m);
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, m, a0, sizeof(a0));
            if (opc == 43 || opc == 86) {
                const char *it = (opc == 43) ? "int" : "uint";
                if (nc == 1) sb_appendf(&sb, "    %s = float(as_type<%s>(%s));\n", ds, it, a0);
                else         sb_appendf(&sb, "    %s = float%d(as_type<%s%d>(%s));\n", ds, nc, it, nc, a0);
            } else {
                const char *it = (opc == 27) ? "int" : "uint";
                if (nc == 1) sb_appendf(&sb, "    %s = as_type<float>(%s(%s));\n", ds, it, a0);
                else         sb_appendf(&sb, "    %s = as_type<float%d>(%s%d(%s));\n", ds, nc, it, nc, a0);
            }
        } else if (opc == 69 || opc == 70 || opc == 71 || opc == 72 || opc == 73 || opc == 74) { /* SAMPLE / SAMPLE_C / SAMPLE_C_LZ / SAMPLE_L / SAMPLE_D / SAMPLE_B */
            DxbcOp stex, ssamp;
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &stex);
            cur = decode_operand(toks, cur, end, &ssamp);
            if (opc == 70 || opc == 71 || opc == 72 || opc == 74) cur = decode_operand(toks, cur, end, &s1);
            else if (opc == 73) { cur = decode_operand(toks, cur, end, &s1); cur = decode_operand(toks, cur, end, &s2); }
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            uint32_t coord_mask = (stex.idx[0] < 16 && (tex_dim[stex.idx[0]] == 3 || tex_dim[stex.idx[0]] == 4)) ? 0x7 : 0x3;
            fmt_src(&s0, coord_mask, a0, sizeof(a0));
            /* Project stex swizzle onto destination write mask */
            char tsw[8], proj[8];
            fmt_swizzle(&stex, tsw);
            int np = 0;
            for (int i = 0; i < 4; i++) if (m & (1U << i)) proj[np++] = tsw[i];
            if (np == 0) strcpy(proj, tsw); else proj[np] = '\0';
            if (stex.idx[0] < 16 && ssamp.idx[0] < 16 && (tex_mask & (1U << stex.idx[0])) && (samp_mask & (1U << ssamp.idx[0]))) {
                if (opc == 70 || opc == 71) { /* SAMPLE_C / SAMPLE_C_LZ */
                    fmt_src(&s1, 0x1, a1, sizeof(a1));
                    const char *lvl = (opc == 71) ? ", level(0.0)" : "";
                    sb_appendf(&sb, "    %s = (float4(float((%s) <= (t%u.sample(s%u, %s%s)).x))).%s;\n",
                               ds, a1, stex.idx[0], ssamp.idx[0], a0, lvl, proj);
                } else if (opc == 72) {
                    fmt_src(&s1, 0x1, a1, sizeof(a1));
                    sb_appendf(&sb, "    %s = (t%u.sample(s%u, %s, level(%s))).%s;\n", ds, stex.idx[0], ssamp.idx[0], a0, a1, proj);
                } else {
                    sb_appendf(&sb, "    %s = (t%u.sample(s%u, %s)).%s;\n", ds, stex.idx[0], ssamp.idx[0], a0, proj);
                }
            } else {
                sb_appendf(&sb, "    %s = (float4(1.0)).%s;\n", ds, proj);
            }
            wrote_dst = 1;
        } else if (opc == 45 || opc == 46) { /* LD / LD_MS */
            DxbcOp stex;
            cur = decode_operand(toks, cur, end, &d);
            cur = decode_operand(toks, cur, end, &s0);
            cur = decode_operand(toks, cur, end, &stex);
            if (opc == 46) cur = decode_operand(toks, cur, end, &s1);
            uint32_t m = d.mask ? d.mask : 0xF;
            fmt_dst(&d, ds, sizeof(ds), dm);
            fmt_src(&s0, 0x3, a0, sizeof(a0));
            if (stex.idx[0] < 16 && (tex_mask & (1U << stex.idx[0]))) {
                sb_appendf(&sb, "    %s = (t%u.read(uint2(as_type<int2>(%s)), 0)).%s;\n", ds, stex.idx[0], a0, dm);
            } else {
                sb_appendf(&sb, "    %s = (float4(0.0)).%s;\n", ds, dm);
            }
            wrote_dst = 1;
        } else if (opc == 13 && out->is_pixel) { /* DISCARD */
            cur = decode_operand(toks, cur, end, &s0);
            fmt_src(&s0, 0x1, a0, sizeof(a0));
            int nz = (tok0 >> 18) & 1;
            sb_appendf(&sb, "    if (as_type<uint>(%s) %s 0u) discard_fragment();\n", a0, nz ? "!=" : "==");
        } else if (opc == 31) { /* IF */
            cur = decode_operand(toks, cur, end, &s0);
            fmt_src(&s0, 0x1, a0, sizeof(a0));
            int nz = (tok0 >> 18) & 1;
            sb_appendf(&sb, "    if (as_type<uint>(%s) %s 0u) {\n", a0, nz ? "!=" : "==");
        } else if (opc == 18) { /* ELSE */
            sb_appendf(&sb, "    } else {\n");
        } else if (opc == 21) { /* ENDIF */
            sb_appendf(&sb, "    }\n");
        } else if (opc == 48) { /* LOOP */
            sb_appendf(&sb, "    while (true) {\n");
        } else if (opc == 22) { /* ENDLOOP */
            sb_appendf(&sb, "    }\n");
        } else if (opc == 2) { /* BREAK */
            sb_appendf(&sb, "    break;\n");
        } else if (opc == 3) { /* BREAKC */
            cur = decode_operand(toks, cur, end, &s0);
            fmt_src(&s0, 0x1, a0, sizeof(a0));
            int nz = (tok0 >> 18) & 1;
            sb_appendf(&sb, "    if (as_type<uint>(%s) %s 0u) break;\n", a0, nz ? "!=" : "==");
        } else if (getenv("ELF64_D3D11_TRACE")) {
            static uint8_t seen_op[256];
            if (opc < 256 && !seen_op[opc]) {
                seen_op[opc] = 1;
                fprintf(stderr, "[dxbc] skipped opcode %u (pixel=%d)\n", opc, out->is_pixel);
            }
        }
        if (sat && wrote_dst) {
            sb_appendf(&sb, "    %s = saturate(%s);\n", ds, ds);
        }
        p = end;
    }

    sb_appendf(&sb, "}\n");
    out->msl_source = sb.data;
    return 0;
}
