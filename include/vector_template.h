/*
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define VILL          ((target_ulong)1 << sizeof(target_ulong) * 8 - 1)
#define SEW_SHIFT     3
#define SEW_MASK      7
#define LMUL_MASK     7
#define LMUL_BOUNDARY (1 << 2)

#define VSTART_MASK (VLEN - 1)
#define VXSAT_MASK  (1 << 0)
#define VXRM_MASK   (3 << 0)
#define VCSR_VXSAT  VXSAT_MASK
#define VCSR_VXRM   (VXRM_MASK << 1)
#define VCSR_MASK   VCSR_VXRM | VCSR_VXSAT

struct RISCVCPUState;

enum width_config { SINGLE_WIDTH, WIDEN_VD_VS2, WIDEN_VD, WIDEN_VS2 };

/* Definitions of "vectorizable" functions, which are expected to perform many times.
 * Each corresponds to one or more vector instruction categories (OPIVV, OPFVV, etc..) */
typedef target_ulong (*Vector_Reg_Access)(RISCVCPUState *, uint8_t, uint8_t);
typedef bool (*Vector_Memory_Op)(RISCVCPUState *, target_ulong, uint8_t *);
typedef void (*Vector_Integer_Op)(RISCVCPUState *, uint8_t *, uint8_t *, void *);

/* Templates for declaration of what will return the relevant "vectorizable" function.
 * Can be thought of as the 'element width config' function. One
 * exists for every vector insn. */
#define V_REG_ACCESS_CONFIG(OP, OP_DEF)                        \
    OP_DEF(8)                                                  \
    OP_DEF(16)                                                 \
    OP_DEF(32)                                                 \
    OP_DEF(64)                                                 \
    static inline Vector_Reg_Access OP##_config(uint8_t eew) { \
        switch (eew) {                                         \
            case 8: return &OP##_e8;                           \
            case 16: return &OP##_e16;                         \
            case 32: return &OP##_e32;                         \
            case 64: return &OP##_e64;                         \
            default: return NULL;                              \
        }                                                      \
    }

#define V_MEM_OP_CONFIG(OP, OP_DEF)                           \
    OP_DEF(8)                                                 \
    OP_DEF(16)                                                \
    OP_DEF(32)                                                \
    OP_DEF(64)                                                \
    static inline Vector_Memory_Op OP##_config(uint8_t eew) { \
        switch (eew) {                                        \
            case 8: return &OP##_e8;                          \
            case 16: return &OP##_e16;                        \
            case 32: return &OP##_e32;                        \
            case 64: return &OP##_e64;                        \
            default: return NULL;                             \
        }                                                     \
    }

#define V_OP_CONFIG(OP, OP_DEF)                                \
    OP_DEF(8)                                                  \
    OP_DEF(16)                                                 \
    OP_DEF(32)                                                 \
    OP_DEF(64)                                                 \
    static inline Vector_Integer_Op OP##_config(uint8_t eew) { \
        switch (eew) {                                         \
            case 8: return &OP##_e8;                           \
            case 16: return &OP##_e16;                         \
            case 32: return &OP##_e32;                         \
            case 64: return &OP##_e64;                         \
            default: return NULL;                              \
        }                                                      \
    }

#define V_WIDEN_OP_CONFIG(OP, OP_DEF)                          \
    OP_DEF(8, 16)                                              \
    OP_DEF(16, 32)                                             \
    OP_DEF(32, 64)                                             \
    static inline Vector_Integer_Op OP##_config(uint8_t eew) { \
        switch (eew) {                                         \
            case 8: return &OP##_e8;                           \
            case 16: return &OP##_e16;                         \
            case 32: return &OP##_e32;                         \
            default: return NULL;                              \
        }                                                      \
    }

/* v_reg_read */
#define V_REG_READ(WIDTH)                                                                 \
    static target_ulong v_reg_read_e##WIDTH(RISCVCPUState *s, uint8_t reg, uint8_t elm) { \
        uint8_t *        ptr = &s->v_reg[reg][elm * (WIDTH >> 3)];                        \
        uint##WIDTH##_t *val = (uint##WIDTH##_t *)ptr;                                    \
        return *val;                                                                      \
    }
// V_REG_ACCESS_CONFIG(v_reg_read, V_REG_READ)

/* v_load */
#define V_LOAD(WIDTH)                                                                \
    static bool v_load_e##WIDTH(RISCVCPUState *s, target_ulong addr, uint8_t *elm) { \
        uint##WIDTH##_t rval;                                                        \
        if (target_read_u##WIDTH(s, &rval, addr))                                    \
            return true;                                                             \
        uint##WIDTH##_t *elm_b = (uint##WIDTH##_t *)elm;                             \
        *elm_b                 = rval;                                               \
        return false;                                                                \
    }

/* v_store */
#define V_STORE(WIDTH)                                                                \
    static bool v_store_e##WIDTH(RISCVCPUState *s, target_ulong addr, uint8_t *elm) { \
        uint##WIDTH##_t *val = (uint##WIDTH##_t *)elm;                                \
        return target_write_u##WIDTH(s, addr, *val);                                  \
    }

/* v_add */
#define V_ADD(WIDTH)                                                                         \
    static void v_add_e##WIDTH(RISCVCPUState *s, uint8_t *vd, uint8_t *vs2, void *val_ptr) { \
        uint##WIDTH##_t *val   = (uint##WIDTH##_t *)val_ptr;                                 \
        uint##WIDTH##_t *vs2_e = (uint##WIDTH##_t *)vs2;                                     \
        uint##WIDTH##_t *vd_e  = (uint##WIDTH##_t *)vd;                                      \
        *vd_e                  = *vs2_e + *val;                                              \
    }
V_OP_CONFIG(v_add, V_ADD)

/* vw_addu */
#define VW_ADDU(WIDTH, WIDTH2)                                                                 \
    static void vw_addu_e##WIDTH(RISCVCPUState *s, uint8_t *vd, uint8_t *vs2, void *val_ptr) { \
        uint##WIDTH##_t * val   = (uint##WIDTH##_t *)val_ptr;                                  \
        uint##WIDTH##_t * vs2_e = (uint##WIDTH##_t *)vs2;                                      \
        uint##WIDTH2##_t *vd_e  = (uint##WIDTH2##_t *)vd;                                      \
        *vd_e                   = *vs2_e + *val;                                               \
    }
V_WIDEN_OP_CONFIG(vw_addu, VW_ADDU)

/* vw_addu.w */
#define VW_ADDUW(WIDTH, WIDTH2)                                                                 \
    static void vw_adduw_e##WIDTH(RISCVCPUState *s, uint8_t *vd, uint8_t *vs2, void *val_ptr) { \
        uint##WIDTH##_t * val   = (uint##WIDTH##_t *)val_ptr;                                   \
        uint##WIDTH2##_t *vs2_e = (uint##WIDTH2##_t *)vs2;                                      \
        uint##WIDTH2##_t *vd_e  = (uint##WIDTH2##_t *)vd;                                       \
        *vd_e                   = *vs2_e + *val;                                                \
    }
V_WIDEN_OP_CONFIG(vw_adduw, VW_ADDUW)

/* vw_add */
#define VW_ADD(WIDTH, WIDTH2)                                                                 \
    static void vw_add_e##WIDTH(RISCVCPUState *s, uint8_t *vd, uint8_t *vs2, void *val_ptr) { \
        int##WIDTH##_t * val   = (int##WIDTH##_t *)val_ptr;                                   \
        int##WIDTH##_t * vs2_e = (int##WIDTH##_t *)vs2;                                       \
        int##WIDTH2##_t *vd_e  = (int##WIDTH2##_t *)vd;                                       \
        *vd_e                  = *vs2_e + *val;                                               \
    }
V_WIDEN_OP_CONFIG(vw_add, VW_ADD)

/* vw_add.w */
#define VW_ADDW(WIDTH, WIDTH2)                                                                 \
    static void vw_addw_e##WIDTH(RISCVCPUState *s, uint8_t *vd, uint8_t *vs2, void *val_ptr) { \
        int##WIDTH##_t * val   = (int##WIDTH##_t *)val_ptr;                                    \
        int##WIDTH2##_t *vs2_e = (int##WIDTH2##_t *)vs2;                                       \
        int##WIDTH2##_t *vd_e  = (int##WIDTH2##_t *)vd;                                        \
        *vd_e                  = *vs2_e + *val;                                                \
    }
V_WIDEN_OP_CONFIG(vw_addw, VW_ADDW)
