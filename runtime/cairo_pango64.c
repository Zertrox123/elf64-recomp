#include "runtime64.h"
#include "win64_abi.h"

#include <ctype.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Win64 -> native Apple Silicon ARM64 bridge for Cairo, Pango, PangoFT2,
 * FreeType, Fontconfig, GLib, and GObject (used by Panorama UI).
 * Loads Homebrew dylibs lazily via dlopen so builds with no Panorama usage
 * have zero runtime dependency on them.
 */

static void *dl_open_brew(const char *name) {
    char p[512];
    const char *ldir = getenv("ELF64_LIB_DIR");
    if (ldir && *ldir) {
        snprintf(p, sizeof(p), "%s/%s", ldir, name);
        void *h = dlopen(p, RTLD_LAZY | RTLD_LOCAL);
        if (h) return h;
    }
    snprintf(p, sizeof(p), "/opt/homebrew/lib/%s", name);
    void *h = dlopen(p, RTLD_LAZY | RTLD_LOCAL);
    if (!h) h = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    return h;
}

static void *g_dl_cairo, *g_dl_pango, *g_dl_pangoft2, *g_dl_ft, *g_dl_fc, *g_dl_gobj, *g_dl_glib;
static int g_dl_init;

static void ensure_dls(void) {
    if (g_dl_init) return;
    g_dl_init = 1;
    g_dl_glib     = dl_open_brew("libglib-2.0.dylib");
    g_dl_gobj     = dl_open_brew("libgobject-2.0.dylib");
    g_dl_ft       = dl_open_brew("libfreetype.dylib");
    g_dl_fc       = dl_open_brew("libfontconfig.dylib");
    g_dl_cairo    = dl_open_brew("libcairo.dylib");
    g_dl_pango    = dl_open_brew("libpango-1.0.dylib");
    g_dl_pangoft2 = dl_open_brew("libpangoft2-1.0.dylib");
}

typedef enum {
    LIB_CAIRO, LIB_PANGO, LIB_PANGOFT2, LIB_FT, LIB_FC, LIB_GOBJ, LIB_GLIB
} NativeLib;

typedef struct {
    NativeLib   lib;
    const char *sym;
    const char *sig; /* ret + args: v=void, i/p=u64/ptr/int, d=double */
    void       *fn;
} CpSpec;

static void *resolve_spec(CpSpec *sp) {
    if (sp->fn) return sp->fn;
    ensure_dls();
    void *h = NULL;
    switch (sp->lib) {
        case LIB_CAIRO:    h = g_dl_cairo; break;
        case LIB_PANGO:    h = g_dl_pango; break;
        case LIB_PANGOFT2: h = g_dl_pangoft2; break;
        case LIB_FT:       h = g_dl_ft; break;
        case LIB_FC:       h = g_dl_fc; break;
        case LIB_GOBJ:     h = g_dl_gobj; break;
        case LIB_GLIB:     h = g_dl_glib; break;
    }
    if (h) sp->fn = dlsym(h, sp->sym);
    return sp->fn;
}

static _Thread_local CPU64 *g_cp_cpu = NULL;

/* Signature-driven Win64 -> ARM64 C trampoline covering all 139 Cairo/Pango/FT/FC/GLib shapes. */
static void cp_trampoline(CPU64 *c, void *ud) {
    CpSpec *sp = (CpSpec *)ud;
    void *fn = resolve_spec(sp);
    if (!fn) { c->rax = 0; return; }
    CPU64 *prev_cpu = g_cp_cpu;
    g_cp_cpu = c;
    const char *s = sp->sig;

    if (strcmp(s, "p") == 0) {
        c->rax = ((uint64_t(*)(void))fn)();
    } else if (strcmp(s, "v") == 0) {
        ((void(*)(void))fn)();
    } else if (strcmp(s, "v_p") == 0) {
        ((void(*)(uint64_t))fn)(win64_arg_i(c, 0));
    } else if (strcmp(s, "p_p") == 0) {
        c->rax = ((uint64_t(*)(uint64_t))fn)(win64_arg_i(c, 0));
    } else if (strcmp(s, "p_pp") == 0) {
        c->rax = ((uint64_t(*)(uint64_t, uint64_t))fn)(win64_arg_i(c, 0), win64_arg_i(c, 1));
    } else if (strcmp(s, "p_ppp") == 0) {
        c->rax = ((uint64_t(*)(uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2));
    } else if (strcmp(s, "p_pppp") == 0) {
        c->rax = ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2), win64_arg_i(c, 3));
    } else if (strcmp(s, "p_ppppp") == 0) {
        c->rax = ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2), win64_arg_i(c, 3), win64_arg_i(c, 4));
    } else if (strcmp(s, "p_pppppp") == 0) {
        c->rax = ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2),
            win64_arg_i(c, 3), win64_arg_i(c, 4), win64_arg_i(c, 5));
    } else if (strcmp(s, "v_pp") == 0) {
        ((void(*)(uint64_t, uint64_t))fn)(win64_arg_i(c, 0), win64_arg_i(c, 1));
    } else if (strcmp(s, "v_ppp") == 0) {
        ((void(*)(uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2));
    } else if (strcmp(s, "v_pppp") == 0) {
        ((void(*)(uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2), win64_arg_i(c, 3));
    } else if (strcmp(s, "v_ppppp") == 0) {
        ((void(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2), win64_arg_i(c, 3), win64_arg_i(c, 4));
    } else if (strcmp(s, "v_pd") == 0) {
        ((void(*)(uint64_t, double))fn)(win64_arg_i(c, 0), win64_arg_d(c, 1));
    } else if (strcmp(s, "v_pdd") == 0) {
        ((void(*)(uint64_t, double, double))fn)(win64_arg_i(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2));
    } else if (strcmp(s, "v_pdddd") == 0) {
        ((void(*)(uint64_t, double, double, double, double))fn)(
            win64_arg_i(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2), win64_arg_d(c, 3), win64_arg_d(c, 4));
    } else if (strcmp(s, "v_pddddd") == 0) {
        ((void(*)(uint64_t, double, double, double, double, double))fn)(
            win64_arg_i(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2),
            win64_arg_d(c, 3), win64_arg_d(c, 4), win64_arg_d(c, 5));
    } else if (strcmp(s, "v_pdddddd") == 0) {
        ((void(*)(uint64_t, double, double, double, double, double, double))fn)(
            win64_arg_i(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2),
            win64_arg_d(c, 3), win64_arg_d(c, 4), win64_arg_d(c, 5), win64_arg_d(c, 6));
    } else if (strcmp(s, "p_dddd") == 0) {
        c->rax = ((uint64_t(*)(double, double, double, double))fn)(
            win64_arg_d(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2), win64_arg_d(c, 3));
    } else if (strcmp(s, "p_dddddd") == 0) {
        c->rax = ((uint64_t(*)(double, double, double, double, double, double))fn)(
            win64_arg_d(c, 0), win64_arg_d(c, 1), win64_arg_d(c, 2),
            win64_arg_d(c, 3), win64_arg_d(c, 4), win64_arg_d(c, 5));
    } else if (strcmp(s, "v_ppppp_d") == 0) {
        /* pango_ft2_render_transformed(bitmap, matrix, font, glyphs, x, y) -> 6 int/ptr args */
        ((void(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(
            win64_arg_i(c, 0), win64_arg_i(c, 1), win64_arg_i(c, 2),
            win64_arg_i(c, 3), win64_arg_i(c, 4), win64_arg_i(c, 5));
    }
    g_cp_cpu = prev_cpu;
}

/* Custom guest PangoAttribute classes hold x86_64 copy/destroy/equal pointers. */
typedef struct HostPangoAttrClass HostPangoAttrClass;
typedef struct {
    const HostPangoAttrClass *klass;
    uint32_t start_index;
    uint32_t end_index;
} HostPangoAttr;

struct HostPangoAttrClass {
    int type;
    HostPangoAttr *(*copy)(const HostPangoAttr *attr);
    void           (*destroy)(HostPangoAttr *attr);
    int            (*equal)(const HostPangoAttr *a, const HostPangoAttr *b);
};

typedef struct {
    HostPangoAttrClass host;
    uint64_t           guest_klass_va;
    uint64_t           guest_copy;
    uint64_t           guest_destroy;
    uint64_t           guest_equal;
} WrappedPangoClass;

static WrappedPangoClass g_pango_classes[32];
static int               g_pango_class_count = 0;
static pthread_mutex_t   g_pango_class_mu = PTHREAD_MUTEX_INITIALIZER;

static HostPangoAttr *host_pango_copy(const HostPangoAttr *attr) {
    if (!attr || !attr->klass) return NULL;
    const WrappedPangoClass *w = (const WrappedPangoClass *)attr->klass;
    if (g_cp_cpu && w->guest_copy > 0x10000ULL) {
        HostPangoAttr *dup = (HostPangoAttr *)(uintptr_t)rt_invoke_win64(
            g_cp_cpu, w->guest_copy, (uint64_t)(uintptr_t)attr, 0, 0, 0, 0, 0);
        if (dup) dup->klass = &w->host;
        return dup;
    }
    HostPangoAttr *dup = (HostPangoAttr *)calloc(1, 64);
    if (dup) { memcpy(dup, attr, 64); dup->klass = &w->host; }
    return dup;
}

static void host_pango_destroy(HostPangoAttr *attr) {
    if (!attr || !attr->klass) return;
    const WrappedPangoClass *w = (const WrappedPangoClass *)attr->klass;
    if (g_cp_cpu && w->guest_destroy > 0x10000ULL) {
        rt_invoke_win64(g_cp_cpu, w->guest_destroy, (uint64_t)(uintptr_t)attr, 0, 0, 0, 0, 0);
    }
}

static int host_pango_equal(const HostPangoAttr *a, const HostPangoAttr *b) {
    if (!a || !b || !a->klass) return a == b;
    const WrappedPangoClass *w = (const WrappedPangoClass *)a->klass;
    if (g_cp_cpu && w->guest_equal > 0x10000ULL) {
        return (int)rt_invoke_win64(g_cp_cpu, w->guest_equal,
                                    (uint64_t)(uintptr_t)a, (uint64_t)(uintptr_t)b, 0, 0, 0, 0);
    }
    return a == b;
}

static void w_pango_attribute_init(CPU64 *c, void *ud) {
    (void)ud;
    ensure_dls();
    typedef void (*InitFn)(void *, const void *);
    InitFn fn = g_dl_pango ? (InitFn)dlsym(g_dl_pango, "pango_attribute_init") : NULL;
    uint64_t attr_va  = c->rcx;
    uint64_t klass_va = c->rdx;
    if (!fn || !attr_va || !klass_va) return;

    pthread_mutex_lock(&g_pango_class_mu);
    WrappedPangoClass *w = NULL;
    for (int i = 0; i < g_pango_class_count; i++) {
        if (g_pango_classes[i].guest_klass_va == klass_va) { w = &g_pango_classes[i]; break; }
    }
    if (!w && g_pango_class_count < 32) {
        w = &g_pango_classes[g_pango_class_count++];
        w->guest_klass_va = klass_va;
        w->host.type      = (int)R32(klass_va + 0);
        w->guest_copy     = R64(klass_va + 8);
        w->guest_destroy  = R64(klass_va + 16);
        w->guest_equal    = R64(klass_va + 24);
        w->host.copy      = host_pango_copy;
        w->host.destroy   = host_pango_destroy;
        w->host.equal     = host_pango_equal;
    }
    pthread_mutex_unlock(&g_pango_class_mu);

    fn((void *)(uintptr_t)attr_va, w ? (const void *)&w->host : (const void *)(uintptr_t)klass_va);
}

static void win_to_px_path(const char *in, char *out, size_t cap) {
    if (!in || cap == 0) { if (cap) out[0] = '\0'; return; }
    if (strncmp(in, "\\\\?\\", 4) == 0) in += 4;
    if (isalpha((unsigned char)in[0]) && in[1] == ':') in += 2;
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < cap; i++) out[j++] = (in[i] == '\\') ? '/' : in[i];
    out[j] = '\0';
}

static void w_FcConfigAppFontAdd(CPU64 *c, void *ud) {
    const char *sym = (const char *)ud;
    ensure_dls();
    typedef int (*Fn)(void *, const unsigned char *);
    Fn fn = g_dl_fc ? (Fn)dlsym(g_dl_fc, sym) : NULL;
    if (!fn || !c->rdx) { c->rax = 0; return; }
    char px[1024];
    win_to_px_path((const char *)(uintptr_t)c->rdx, px, sizeof(px));
    c->rax = (uint64_t)fn((void *)(uintptr_t)c->rcx, (const unsigned char *)px);
}

typedef struct { int type; uint32_t _pad; uint64_t u; } HostFcValue;

/* On Win64, 16-byte FcValue is passed by pointer in r8; on ARM64 AAPCS64 by value in x2/x3. */
static void w_FcPatternAdd(CPU64 *c, void *ud) {
    (void)ud;
    ensure_dls();
    typedef int (*Fn)(void *, const char *, HostFcValue, int);
    Fn fn = g_dl_fc ? (Fn)dlsym(g_dl_fc, "FcPatternAdd") : NULL;
    if (!fn || !c->r8) { c->rax = 0; return; }
    HostFcValue v;
    v.type = (int)R32(c->r8);
    v._pad = 0;
    v.u    = R64(c->r8 + 8);
    c->rax = (uint64_t)fn((void *)(uintptr_t)c->rcx, (const char *)(uintptr_t)c->rdx, v, (int)c->r9);
}

static void w_noop_zero(CPU64 *c, void *ud) { (void)ud; c->rax = 0; }

static CpSpec g_cp_specs[] = {
    /* Cairo (46) */
    { LIB_CAIRO, "cairo_arc", "v_pddddd", NULL },
    { LIB_CAIRO, "cairo_arc_negative", "v_pddddd", NULL },
    { LIB_CAIRO, "cairo_clip", "v_p", NULL },
    { LIB_CAIRO, "cairo_close_path", "v_p", NULL },
    { LIB_CAIRO, "cairo_create", "p_p", NULL },
    { LIB_CAIRO, "cairo_curve_to", "v_pdddddd", NULL },
    { LIB_CAIRO, "cairo_debug_reset_static_data", "v", NULL },
    { LIB_CAIRO, "cairo_destroy", "v_p", NULL },
    { LIB_CAIRO, "cairo_fill", "v_p", NULL },
    { LIB_CAIRO, "cairo_fill_preserve", "v_p", NULL },
    { LIB_CAIRO, "cairo_get_current_point", "v_ppp", NULL },
    { LIB_CAIRO, "cairo_get_matrix", "v_pp", NULL },
    { LIB_CAIRO, "cairo_has_current_point", "p_p", NULL },
    { LIB_CAIRO, "cairo_image_surface_create_for_data", "p_ppppp", NULL },
    { LIB_CAIRO, "cairo_line_to", "v_pdd", NULL },
    { LIB_CAIRO, "cairo_matrix_init", "v_pdddddd", NULL },
    { LIB_CAIRO, "cairo_move_to", "v_pdd", NULL },
    { LIB_CAIRO, "cairo_new_path", "v_p", NULL },
    { LIB_CAIRO, "cairo_paint", "v_p", NULL },
    { LIB_CAIRO, "cairo_paint_with_alpha", "v_pd", NULL },
    { LIB_CAIRO, "cairo_pattern_add_color_stop_rgba", "v_pddddd", NULL },
    { LIB_CAIRO, "cairo_pattern_create_linear", "p_dddd", NULL },
    { LIB_CAIRO, "cairo_pattern_create_radial", "p_dddddd", NULL },
    { LIB_CAIRO, "cairo_pattern_destroy", "v_p", NULL },
    { LIB_CAIRO, "cairo_pop_group_to_source", "v_p", NULL },
    { LIB_CAIRO, "cairo_push_group", "v_p", NULL },
    { LIB_CAIRO, "cairo_rectangle", "v_pdddd", NULL },
    { LIB_CAIRO, "cairo_rel_curve_to", "v_pdddddd", NULL },
    { LIB_CAIRO, "cairo_rel_line_to", "v_pdd", NULL },
    { LIB_CAIRO, "cairo_rel_move_to", "v_pdd", NULL },
    { LIB_CAIRO, "cairo_restore", "v_p", NULL },
    { LIB_CAIRO, "cairo_rotate", "v_pd", NULL },
    { LIB_CAIRO, "cairo_save", "v_p", NULL },
    { LIB_CAIRO, "cairo_scale", "v_pdd", NULL },
    { LIB_CAIRO, "cairo_set_fill_rule", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_line_cap", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_line_join", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_line_width", "v_pd", NULL },
    { LIB_CAIRO, "cairo_set_matrix", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_operator", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_source", "v_pp", NULL },
    { LIB_CAIRO, "cairo_set_source_rgba", "v_pdddd", NULL },
    { LIB_CAIRO, "cairo_stroke", "v_p", NULL },
    { LIB_CAIRO, "cairo_surface_destroy", "v_p", NULL },
    { LIB_CAIRO, "cairo_transform", "v_pp", NULL },
    { LIB_CAIRO, "cairo_translate", "v_pdd", NULL },
    /* FreeType (4) */
    { LIB_FT, "FT_Get_Char_Index", "p_pp", NULL },
    { LIB_FT, "FT_Get_Kerning", "p_ppppp", NULL },
    { LIB_FT, "FT_Load_Glyph", "p_ppp", NULL },
    { LIB_FT, "FT_New_Memory_Face", "p_ppppp", NULL },
    /* GLib / GObject (3) */
    { LIB_GLIB, "g_free", "v_p", NULL },
    { LIB_GOBJ, "g_object_unref", "v_p", NULL },
    { LIB_GOBJ, "g_type_check_instance_cast", "p_pp", NULL },
    /* Pango (77) */
    { LIB_PANGO, "pango_attr_family_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_letter_spacing_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_list_change", "v_pp", NULL },
    { LIB_PANGO, "pango_attr_list_insert", "v_pp", NULL },
    { LIB_PANGO, "pango_attr_list_new", "p", NULL },
    { LIB_PANGO, "pango_attr_list_unref", "v_p", NULL },
    { LIB_PANGO, "pango_attr_shape_new", "p_pp", NULL },
    { LIB_PANGO, "pango_attr_size_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_strikethrough_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_style_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_type_register", "p_p", NULL },
    { LIB_PANGO, "pango_attr_underline_new", "p_p", NULL },
    { LIB_PANGO, "pango_attr_weight_new", "p_p", NULL },
    { LIB_PANGO, "pango_attribute_init", "v_pp", NULL },
    { LIB_PANGO, "pango_context_get_font_map", "p_p", NULL },
    { LIB_PANGO, "pango_context_get_language", "p_p", NULL },
    { LIB_PANGO, "pango_context_get_metrics", "p_ppp", NULL },
    { LIB_PANGO, "pango_context_set_base_dir", "v_pp", NULL },
    { LIB_PANGO, "pango_context_set_language", "v_pp", NULL },
    { LIB_PANGO, "pango_extents_to_pixels", "v_pp", NULL },
    { LIB_PANGO, "pango_font_describe", "p_p", NULL },
    { LIB_PANGO, "pango_font_description_free", "v_p", NULL },
    { LIB_PANGO, "pango_font_description_from_string", "p_p", NULL },
    { LIB_PANGO, "pango_font_description_set_size", "v_pp", NULL },
    { LIB_PANGO, "pango_font_description_set_style", "v_pp", NULL },
    { LIB_PANGO, "pango_font_description_set_weight", "v_pp", NULL },
    { LIB_PANGO, "pango_font_description_to_string", "p_p", NULL },
    { LIB_PANGO, "pango_font_family_get_name", "p_p", NULL },
    { LIB_PANGO, "pango_font_get_metrics", "p_pp", NULL },
    { LIB_PANGO, "pango_font_map_create_context", "p_p", NULL },
    { LIB_PANGO, "pango_font_map_list_families", "v_ppp", NULL },
    { LIB_PANGO, "pango_font_map_load_font", "p_ppp", NULL },
    { LIB_PANGO, "pango_font_metrics_get_ascent", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_get_descent", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_get_strikethrough_position", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_get_strikethrough_thickness", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_get_underline_position", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_get_underline_thickness", "p_p", NULL },
    { LIB_PANGO, "pango_font_metrics_unref", "v_p", NULL },
    { LIB_PANGO, "pango_language_from_string", "p_p", NULL },
    { LIB_PANGO, "pango_layout_context_changed", "v_p", NULL },
    { LIB_PANGO, "pango_layout_get_attributes", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_ellipsize", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_font_description", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_height", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_iter", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_line_count", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_line_readonly", "p_pp", NULL },
    { LIB_PANGO, "pango_layout_get_pixel_extents", "v_ppp", NULL },
    { LIB_PANGO, "pango_layout_get_text", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_width", "p_p", NULL },
    { LIB_PANGO, "pango_layout_get_wrap", "p_p", NULL },
    { LIB_PANGO, "pango_layout_index_to_line_x", "v_ppppp", NULL },
    { LIB_PANGO, "pango_layout_index_to_pos", "v_ppp", NULL },
    { LIB_PANGO, "pango_layout_is_ellipsized", "p_p", NULL },
    { LIB_PANGO, "pango_layout_is_wrapped", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_free", "v_p", NULL },
    { LIB_PANGO, "pango_layout_iter_get_baseline", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_get_index", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_get_line_extents", "v_ppp", NULL },
    { LIB_PANGO, "pango_layout_iter_get_line_readonly", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_get_run_extents", "v_ppp", NULL },
    { LIB_PANGO, "pango_layout_iter_get_run_readonly", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_next_line", "p_p", NULL },
    { LIB_PANGO, "pango_layout_iter_next_run", "p_p", NULL },
    { LIB_PANGO, "pango_layout_line_get_x_ranges", "v_ppppp", NULL },
    { LIB_PANGO, "pango_layout_new", "p_p", NULL },
    { LIB_PANGO, "pango_layout_set_alignment", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_attributes", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_auto_dir", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_ellipsize", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_font_description", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_height", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_text", "v_ppp", NULL },
    { LIB_PANGO, "pango_layout_set_width", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_set_wrap", "v_pp", NULL },
    { LIB_PANGO, "pango_layout_xy_to_index", "p_ppppp", NULL },
    /* PangoFT2 (5 native + 1 Valve custom) */
    { LIB_PANGOFT2, "pango_fc_font_get_type", "p", NULL },
    { LIB_PANGOFT2, "pango_fc_font_lock_face", "p_p", NULL },
    { LIB_PANGOFT2, "pango_fc_font_unlock_face", "v_p", NULL },
    { LIB_PANGOFT2, "pango_ft2_font_map_new", "p", NULL },
    { LIB_PANGOFT2, "pango_ft2_render_transformed", "v_ppppp_d", NULL },
    /* Fontconfig (8) */
    { LIB_FC, "FcConfigSetCurrent", "p_p", NULL },
    { LIB_FC, "FcConfigSubstitute", "p_ppp", NULL },
    { LIB_FC, "FcDefaultSubstitute", "v_p", NULL },
    { LIB_FC, "FcFontMatch", "p_ppp", NULL },
    { LIB_FC, "FcInitLoadConfigAndFonts", "p", NULL },
    { LIB_FC, "FcPatternCreate", "p", NULL },
    { LIB_FC, "FcPatternDestroy", "v_p", NULL },
    { LIB_FC, "FcPatternGetString", "p_pppp", NULL },
};

void rt_register_cairo_pango_64(void) {
    for (size_t i = 0; i < sizeof(g_cp_specs) / sizeof(g_cp_specs[0]); i++) {
        rt_register_shim(g_cp_specs[i].sym, cp_trampoline, &g_cp_specs[i]);
    }
    rt_register_shim("FcConfigAppFontAddDir", w_FcConfigAppFontAdd, (void *)"FcConfigAppFontAddDir");
    rt_register_shim("FcConfigAppFontAddFile", w_FcConfigAppFontAdd, (void *)"FcConfigAppFontAddFile");
    rt_register_shim("FcPatternAdd", w_FcPatternAdd, NULL);
    rt_register_shim("pango_attribute_init", w_pango_attribute_init, NULL);
    /* Valve-custom hooks absent from upstream Pango/Fontconfig */
    rt_register_shim("pango_ft2_new_face_substitute", w_noop_zero, NULL);
    rt_register_shim("fontconfig_ft2_new_face_substitute", w_noop_zero, NULL);
}
