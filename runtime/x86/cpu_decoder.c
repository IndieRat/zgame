/*
 * XWASM IA-32 decoder front-end.
 *
 * This file is included by runtime.c after the guest CPU state/helpers are
 * defined.  The decoder owns instruction-boundary parsing and lookup; the
 * legacy executor remains behind it until each semantic family is migrated.
 */
#include "generated_decode_table.h"

typedef struct {
    uint32_t start;
    uint32_t cursor;
    uint8_t prefixes;
    uint8_t operand16;
    uint8_t address16;
    uint8_t map;
    uint8_t opcode;
    uint8_t modrm;
    uint8_t has_modrm;
    uint8_t sib;
    uint8_t has_sib;
    uint8_t disp_size;
    uint8_t imm_size;
    uint8_t rel_size;
    int8_t modrm_ext;
    uint8_t x87;        /* 1 when the opcode is in D8..DF (x87 escape) */
    uint32_t op_pos;    /* address of the opcode byte (after any prefixes) */
    const x86_decode_entry_t *entry;
} x86_decoded_t;

#define X86_PREFIX_LOCK 0x01u
#define X86_PREFIX_REPNZ 0x02u
#define X86_PREFIX_REP 0x04u
#define X86_PREFIX_SEG 0x08u
#define X86_PREFIX_OP16 0x10u
#define X86_PREFIX_FS 0x40u
#define X86_PREFIX_GS 0x80u
#define X86_PREFIX_ADDR16 0x20u

static int x86_is_prefix(uint8_t b) {
    switch (b) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65:
        case 0x66: case 0x67:
            return 1;
        default:
            return 0;
    }
}

static void x86_record_prefix(x86_decoded_t *d, uint8_t b) {
    if (b == 0xF0) d->prefixes |= X86_PREFIX_LOCK;
    else if (b == 0xF2) d->prefixes |= X86_PREFIX_REPNZ;
    else if (b == 0xF3) d->prefixes |= X86_PREFIX_REP;
    else if (b == 0x66) { d->prefixes |= X86_PREFIX_OP16; d->operand16 ^= 1u; }
    else if (b == 0x67) { d->prefixes |= X86_PREFIX_ADDR16; d->address16 ^= 1u; }
    else if (b == 0x64) { d->prefixes |= X86_PREFIX_SEG | X86_PREFIX_FS; }
    else if (b == 0x65) { d->prefixes |= X86_PREFIX_SEG | X86_PREFIX_GS; }
    else d->prefixes |= X86_PREFIX_SEG;
}

static const x86_decode_entry_t *x86_find_entry(uint8_t map, uint8_t opcode,
                                                 int has_modrm, uint8_t modrm, uint8_t prefixes) {
    const x86_decode_entry_t *best = 0;
    for (uint32_t i = 0; i < X86_DECODE_TABLE_COUNT; ++i) {
        const x86_decode_entry_t *e = &x86_decode_table[i];
        if (e->map != map || e->opcode != opcode) continue;
        if (e->needs_modrm != (uint8_t)has_modrm) continue;
        if (e->prefix_mask && (prefixes & e->prefix_mask) != e->prefix_value) continue;
        if (e->modrm_ext >= 0) {
            if (!has_modrm || ((modrm >> 3) & 7u) != (uint8_t)e->modrm_ext) continue;
        }
        best = e;
        break;
    }
    return best;
}

static int x86_decode_modrm_tail(x86_decoded_t *d) {
    uint8_t m = d->modrm;
    uint8_t mod = m >> 6;
    uint8_t rm = m & 7u;

    if (mod == 3) return 0;

    if (d->address16) {
        d->disp_size = (mod == 0 && rm == 6) ? 2 : (mod == 1 ? 1 : (mod == 2 ? 2 : 0));
        d->cursor += d->disp_size;
        return 0;
    }

    if (rm == 4) {
        d->has_sib = 1;
        d->sib = MEM8(d->cursor++);
        uint8_t base = d->sib & 7u;
        if (mod == 0 && base == 5) d->disp_size = 4;
    } else if (mod == 0 && rm == 5) {
        d->disp_size = 4;
    }
    if (mod == 1) d->disp_size = 1;
    else if (mod == 2) d->disp_size = 4;
    d->cursor += d->disp_size;
    return 0;
}

static int x86_id_is(const char *a,const char *b){while(*a&&*b){if(*a++!=*b++)return 0;}return *a==0&&*b==0;}

static void x86_decode_payload_size(x86_decoded_t *d) {
    const char *id = d->entry ? d->entry->id : 0;
    if (!id) return;
    if (x86_id_is(id, "RET_IMM16")) d->imm_size = 2;
    if (x86_id_is(id, "MOV_R8_IMM8") || x86_id_is(id, "MOV_RM8_IMM8")) d->imm_size = 1;
    if (x86_id_is(id, "MOV_AL_MOFFS8") || x86_id_is(id, "MOV_EAX_MOFFS32") || x86_id_is(id, "MOV_MOFFS8_AL") || x86_id_is(id, "MOV_MOFFS32_EAX")) d->imm_size = 4;
    if (x86_id_is(id, "OR_EAX_IMM32") || x86_id_is(id, "SBB_EAX_IMM32") || x86_id_is(id, "TEST_EAX_IMM32")) d->imm_size = 4;
    if (x86_id_is(id, "TEST_AL_IMM8")) d->imm_size = 1;

    else if (x86_id_is(id, "MOV_R32_IMM32") && !d->operand16) d->imm_size = 4;
    else if (x86_id_is(id, "XOR_EAX_IMM32")) d->imm_size = 4;
    else if (x86_id_is(id, "MOV_R32_IMM32") && d->operand16) d->imm_size = 2;
    else if (d->operand16 &&
             (x86_id_is(id, "ADD_EAX_IMM32") ||
              x86_id_is(id, "SUB_EAX_IMM32") ||
              x86_id_is(id, "CMP_EAX_IMM32") ||
              x86_id_is(id, "ADC_EAX_IMM32") ||
              x86_id_is(id, "SBB_EAX_IMM32") ||
              x86_id_is(id, "PUSH_IMM32") ||
              x86_id_is(id, "IMUL_R32_RM32_IMM32"))) d->imm_size = 2;
    else if (x86_id_is(id, "MOV_R32_IMM32") ||
        x86_id_is(id, "MOV_RM32_IMM32") ||
        x86_id_is(id, "ADD_RM32_IMM32") ||
        x86_id_is(id, "SUB_RM32_IMM32") ||
        x86_id_is(id, "CMP_RM32_IMM32") ||
        x86_id_is(id, "XOR_RM32_IMM32") ||
        x86_id_is(id, "ADC_RM32_IMM32") ||
        x86_id_is(id, "SBB_RM32_IMM32") ||
        x86_id_is(id, "IMUL_R32_RM32_IMM32") ||
        x86_id_is(id, "AND_EAX_IMM32") ||
        x86_id_is(id, "TEST_RM32_IMM32") ||
        x86_id_is(id, "ADD_EAX_IMM32") ||
        x86_id_is(id, "SUB_EAX_IMM32") ||
        x86_id_is(id, "CMP_EAX_IMM32") ||
        x86_id_is(id, "PUSH_IMM32")) d->imm_size = 4;
    else if (x86_id_is(id, "ROL_RM8_IMM8") || x86_id_is(id, "ROR_RM8_IMM8") || x86_id_is(id, "RCL_RM8_IMM8") || x86_id_is(id, "RCR_RM8_IMM8") || x86_id_is(id, "SHL_RM8_IMM8") || x86_id_is(id, "SHR_RM8_IMM8") || x86_id_is(id, "SAL_RM8_IMM8") || x86_id_is(id, "SAR_RM8_IMM8") || x86_id_is(id, "ROL_RM32_IMM8") || x86_id_is(id, "ROR_RM32_IMM8") || x86_id_is(id, "RCL_RM32_IMM8") || x86_id_is(id, "RCR_RM32_IMM8") || x86_id_is(id, "SHL_RM32_IMM8") || x86_id_is(id, "SHR_RM32_IMM8") || x86_id_is(id, "SAL_RM32_IMM8") || x86_id_is(id, "SAR_RM32_IMM8") ||
             x86_id_is(id, "ROL_RM8_CL") || x86_id_is(id, "ROR_RM8_CL") || x86_id_is(id, "RCL_RM8_CL") || x86_id_is(id, "RCR_RM8_CL") || x86_id_is(id, "SHL_RM8_CL") || x86_id_is(id, "SHR_RM8_CL") || x86_id_is(id, "SAL_RM8_CL") || x86_id_is(id, "SAR_RM8_CL") || x86_id_is(id, "ROL_RM32_CL") || x86_id_is(id, "ROR_RM32_CL") || x86_id_is(id, "RCL_RM32_CL") || x86_id_is(id, "RCR_RM32_CL") || x86_id_is(id, "SHL_RM32_CL") || x86_id_is(id, "SHR_RM32_CL") || x86_id_is(id, "SAL_RM32_CL") || x86_id_is(id, "SAR_RM32_CL")) d->imm_size = 1;
    else if (x86_id_is(id, "ADD_RM32_IMM8") ||
             x86_id_is(id, "AND_RM32_IMM8") ||
             x86_id_is(id, "SUB_RM32_IMM8") ||
             x86_id_is(id, "CMP_RM32_IMM8") ||
             x86_id_is(id, "ADC_RM32_IMM8") ||
             x86_id_is(id, "SBB_RM32_IMM8") ||
             x86_id_is(id, "OR_RM32_IMM8") ||
             x86_id_is(id, "XOR_RM32_IMM8") ||
             x86_id_is(id, "SHL_RM32_IMM8") ||
             x86_id_is(id, "SHR_RM32_IMM8") ||
             x86_id_is(id, "SAR_RM32_IMM8") ||
             x86_id_is(id, "ROL_RM32_IMM8") ||
             x86_id_is(id, "ROR_RM32_IMM8") ||
             x86_id_is(id, "RCL_RM32_IMM8") ||
             x86_id_is(id, "RCR_RM32_IMM8") ||
             x86_id_is(id, "IMUL_R32_RM32_IMM8") ||
             x86_id_is(id, "BT_RM32_IMM8") ||
             x86_id_is(id, "BTS_RM32_IMM8") ||
             x86_id_is(id, "BTR_RM32_IMM8") ||
             x86_id_is(id, "BTC_RM32_IMM8") ||
             x86_id_is(id, "ADD_AL_IMM8") || 
             x86_id_is(id, "OR_AL_IMM8") ||
             x86_id_is(id, "ADC_AL_IMM8") || 
             x86_id_is(id, "SBB_AL_IMM8") ||
             x86_id_is(id, "AND_AL_IMM8") || 
             x86_id_is(id, "SUB_AL_IMM8") ||
             x86_id_is(id, "XOR_AL_IMM8") || 
             x86_id_is(id, "CMP_AL_IMM8") ||
             x86_id_is(id, "ADD_RM8_IMM8") || 
             x86_id_is(id, "ADC_RM8_IMM8") ||
             x86_id_is(id, "SBB_RM8_IMM8") || 
             x86_id_is(id, "AND_RM8_IMM8") ||
             x86_id_is(id, "SUB_RM8_IMM8") || 
             x86_id_is(id, "XOR_RM8_IMM8") ||
             x86_id_is(id, "CMP_RM8_IMM8") || 
             x86_id_is(id, "PUSH_IMM8")) d->imm_size = 1;
    else if (x86_id_is(id, "CALL_REL32") ||
             x86_id_is(id, "JMP_REL32") ||
             x86_id_is(id, "JO_REL32") ||
             x86_id_is(id, "JNO_REL32") ||
             x86_id_is(id, "JB_REL32") ||
             x86_id_is(id, "JAE_REL32") ||
             x86_id_is(id, "JE_REL32") ||
             x86_id_is(id, "JNE_REL32") ||
             x86_id_is(id, "JBE_REL32") ||
             x86_id_is(id, "JA_REL32") ||
             x86_id_is(id, "JS_REL32") ||
             x86_id_is(id, "JNS_REL32") ||
             x86_id_is(id, "JP_REL32") ||
             x86_id_is(id, "JNP_REL32") ||
             x86_id_is(id, "JL_REL32") ||
             x86_id_is(id, "JGE_REL32") ||
             x86_id_is(id, "JLE_REL32") ||
             x86_id_is(id, "JG_REL32")) d->rel_size = 4;
    else if (x86_id_is(id, "JMP_REL8") ||
             x86_id_is(id, "JE_REL8") ||
             x86_id_is(id, "JNE_REL8") ||
             x86_id_is(id, "JB_REL8") ||
             x86_id_is(id, "JAE_REL8") ||
             x86_id_is(id, "JA_REL8") ||
             x86_id_is(id, "JBE_REL8") ||
             x86_id_is(id, "JL_REL8") ||
             x86_id_is(id, "JGE_REL8") ||
             x86_id_is(id, "JLE_REL8") ||
             x86_id_is(id, "JG_REL8") ||
             x86_id_is(id, "JO_REL8") ||
             x86_id_is(id, "JNO_REL8") ||
             x86_id_is(id, "JS_REL8") ||
             x86_id_is(id, "JNS_REL8") ||
             x86_id_is(id, "JP_REL8") ||
             x86_id_is(id, "JNP_REL8") ||
             x86_id_is(id, "JCXZ_REL8") ||
             x86_id_is(id, "LOOP_REL8") ||
             x86_id_is(id, "LOOPE_REL8") ||
             x86_id_is(id, "LOOPNE_REL8")) d->rel_size = 1;
}
static int x86_decode_instruction(x86_decoded_t *d) {
    d->start = eip;
    d->cursor = eip;
    d->prefixes = 0;
    d->operand16 = 0;
    d->address16 = 0;
    d->map = 0;
    d->opcode = 0;
    d->modrm = 0;
    d->has_modrm = 0;
    d->sib = 0;
    d->has_sib = 0;
    d->disp_size = 0;
    d->imm_size = 0;
    d->rel_size = 0;
    d->modrm_ext = -1;
    d->x87 = 0;
    d->op_pos = 0;
    d->entry = 0;

    for (uint32_t n = 0; n < 15u && x86_is_prefix(MEM8(d->cursor)); ++n) {
        x86_record_prefix(d, MEM8(d->cursor++));
    }

    if (d->cursor - d->start >= 15u) {
        cpu_error = 0xD001u;
        return -1;
    }

    d->opcode = MEM8(d->cursor++);
    d->op_pos = d->cursor - 1u;
    if (d->opcode == 0x0F) {
        d->map = 1;
        if (MEM8(d->cursor) == 0x38 || MEM8(d->cursor) == 0x3A) {
            /* Three-byte maps are decoded structurally now; execution is
             * intentionally rejected until their semantic families land. */
            d->map = MEM8(d->cursor++) == 0x38 ? 2 : 3;
        }
        d->opcode = MEM8(d->cursor++);
    }

    /* x87 escape opcodes D8..DF. ModR/M selects the operation (including the
     * register forms such as DE C9 = FMULP ST(1),ST(0) and DE D9 = FCOMPP), so
     * these are not looked up in the semantic table. The x87 executor decodes
     * ModR/M, displacement and the final instruction length itself. */
    if (d->map == 0 && d->opcode >= 0xD8 && d->opcode <= 0xDF) {
        static const x86_decode_entry_t x87_entry = {0,0,1,-1,"X87",0,0};
        if (d->address16) {
            cpu_error = 0xD100u | d->opcode;
            return -3;
        }
        d->x87 = 1;
        d->op_pos = d->cursor - 1u;
        d->entry = &x87_entry;
        return 0;
    }

    /* First locate an opcode candidate without consuming ModR/M. */
    if (!d->entry) d->entry = x86_find_entry(d->map, d->opcode, 0, 0, d->prefixes);

    /* If there is no fixed-form entry, try the ModR/M forms. */
    if (!d->entry) {
        d->entry = x86_find_entry(d->map, d->opcode, 1, MEM8(d->cursor), d->prefixes);
        if (d->entry) {
            d->has_modrm = 1;
            d->modrm = MEM8(d->cursor++);
            d->modrm_ext = (int8_t)((d->modrm >> 3) & 7u);
            x86_decode_modrm_tail(d);
        }
    } else if (d->entry->needs_modrm) {
        d->has_modrm = 1;
        d->modrm = MEM8(d->cursor++);
        d->modrm_ext = (int8_t)((d->modrm >> 3) & 7u);
        x86_decode_modrm_tail(d);
    }

    if (!d->entry) {
        /* Opcode forms that use an opcode-embedded register are represented
         * by one entry for several opcode bytes in the JSON database. */
        if (d->map == 0) {
            if ((d->opcode >= 0xB0 && d->opcode <= 0xB7) ||
                (d->opcode >= 0xB8 && d->opcode <= 0xBF) ||
                (d->opcode >= 0x40 && d->opcode <= 0x4F) ||
                (d->opcode >= 0x50 && d->opcode <= 0x5F)) {
                d->entry = x86_find_entry(0, d->opcode, 0, 0, d->prefixes);
            }
        }
    }

    if (!d->entry) {
        cpu_error = 0xD000u | d->opcode;
        return -2;
    }

    x86_decode_payload_size(d);
    if(d->imm_size){if(d->cursor-d->start+d->imm_size>15u){cpu_error=0xD003u;return -5;}d->cursor+=d->imm_size;}
    if(d->rel_size){if(d->cursor-d->start+d->rel_size>15u){cpu_error=0xD004u;return -6;}d->cursor+=d->rel_size;}

    /* Operand-size/address-size overrides are decoded correctly, but the
     * current semantic executor only consumes 32-bit forms. */
    if (d->address16) {
        cpu_error = 0xD100u | d->opcode;
        return -3;
    }
    if (d->operand16) {
        int string16 = x86_id_is(d->entry->id, "MOVSW") ||
                       x86_id_is(d->entry->id, "CMPSW") ||
                       x86_id_is(d->entry->id, "SCASW") ||
                       x86_id_is(d->entry->id, "LODSW") ||
                       x86_id_is(d->entry->id, "STOSW");
        int group2_16 = x86_id_is(d->entry->id, "SHL_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "SHR_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "SAR_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "ROL_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "ROR_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "RCL_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "RCR_RM32_IMM8") ||
                        x86_id_is(d->entry->id, "SHL_RM32_1") ||
                        x86_id_is(d->entry->id, "SHR_RM32_1") ||
                        x86_id_is(d->entry->id, "SAR_RM32_1") ||
                        x86_id_is(d->entry->id, "ROL_RM32_1") ||
                        x86_id_is(d->entry->id, "ROR_RM32_1") ||
                        x86_id_is(d->entry->id, "RCL_RM32_1") ||
                        x86_id_is(d->entry->id, "RCR_RM32_1") ||
                        x86_id_is(d->entry->id, "SHL_RM32_CL") ||
                        x86_id_is(d->entry->id, "SHR_RM32_CL") ||
                        x86_id_is(d->entry->id, "SAR_RM32_CL") ||
                        x86_id_is(d->entry->id, "ROL_RM32_CL") ||
                        x86_id_is(d->entry->id, "ROR_RM32_CL") ||
                        x86_id_is(d->entry->id, "RCL_RM32_CL") ||
                        x86_id_is(d->entry->id, "RCR_RM32_CL");
        if (!string16 && !group2_16 &&
            !x86_id_is(d->entry->id, "MOV_R32_IMM32") &&
            !x86_id_is(d->entry->id, "ADD_EAX_IMM32") &&
            !x86_id_is(d->entry->id, "SUB_EAX_IMM32") &&
            !x86_id_is(d->entry->id, "CMP_EAX_IMM32") &&
            !x86_id_is(d->entry->id, "MOV_RM16_SREG") &&
            !x86_id_is(d->entry->id, "MOV_SREG_RM16") &&
            !x86_id_is(d->entry->id, "MOVZX_R32_RM16")) {
            cpu_error = 0xD100u | d->opcode;
            return -3;
        }
    }

    if (d->cursor - d->start > 15u) {
        cpu_error = 0xD002u;
        return -4;
    }

    return 0;
}

/* Accurate semantic names for the x87 trace. DC/DE use the Intel encoding in
 * which the SUB/SUBR and DIV/DIVR slots are swapped relative to D8. */
static const char *x87_semantic_name(uint8_t op, uint8_t m, char *buf) {
    static const char *const mem[8][8] = {
        {"FADD_M32","FMUL_M32","FCOM_M32","FCOMP_M32","FSUB_M32","FSUBR_M32","FDIV_M32","FDIVR_M32"},
        {"FLD_M32","X87_D9_1","FST_M32","FSTP_M32","FLDENV","FLDCW","FNSTENV","FNSTCW"},
        {"FIADD_M32","FIMUL_M32","FICOM_M32","FICOMP_M32","FISUB_M32","FISUBR_M32","FIDIV_M32","FIDIVR_M32"},
        {"FILD_M32","FISTTP_M32","FIST_M32","FISTP_M32","X87_DB_4","FLD_M80","X87_DB_6","FSTP_M80"},
        {"FADD_M64","FMUL_M64","FCOM_M64","FCOMP_M64","FSUB_M64","FSUBR_M64","FDIV_M64","FDIVR_M64"},
        {"FLD_M64","FISTTP_M64","FST_M64","FSTP_M64","FRSTOR","X87_DD_5","FNSAVE","FNSTSW"},
        {"FIADD_M16","FIMUL_M16","FICOM_M16","FICOMP_M16","FISUB_M16","FISUBR_M16","FIDIV_M16","FIDIVR_M16"},
        {"FILD_M16","FISTTP_M16","FIST_M16","FISTP_M16","FBLD","FILD_M64","FBSTP","FISTP_M64"}
    };
    static const char *const d8[8] = {"FADD_ST0_STI","FMUL_ST0_STI","FCOM_STI","FCOMP_STI","FSUB_ST0_STI","FSUBR_ST0_STI","FDIV_ST0_STI","FDIVR_ST0_STI"};
    static const char *const dc[8] = {"FADD_STI_ST0","FMUL_STI_ST0",0,0,"FSUBR_STI_ST0","FSUB_STI_ST0","FDIVR_STI_ST0","FDIV_STI_ST0"};
    static const char *const de[8] = {"FADDP_STI_ST0","FMULP_STI_ST0",0,0,"FSUBRP_STI_ST0","FSUBP_STI_ST0","FDIVRP_STI_ST0","FDIVP_STI_ST0"};
    static const char hex[] = "0123456789ABCDEF";
    uint8_t reg = (m >> 3) & 7u, i = (uint8_t)(op - 0xD8u);
    const char *n = 0;
    if ((m >> 6) != 3u) n = mem[i][reg];
    else if (op == 0xD8u) n = d8[reg];
    else if (op == 0xDCu) n = dc[reg];
    else if (op == 0xDEu) n = (m == 0xD9u) ? "FCOMPP" : de[reg];
    else if (op == 0xD9u) {
        if ((m & 0xF8u) == 0xC0u) n = "FLD_STI";
        else if ((m & 0xF8u) == 0xC8u) n = "FXCH_STI";
        else switch (m) {
            case 0xD0: n = "FNOP"; break;   case 0xE0: n = "FCHS"; break;
            case 0xE1: n = "FABS"; break;   case 0xE4: n = "FTST"; break;
            case 0xE5: n = "FXAM"; break;   case 0xE8: n = "FLD1"; break;
            case 0xEE: n = "FLDZ"; break;   case 0xF6: n = "FDECSTP"; break;
            case 0xF7: n = "FINCSTP"; break; default: break;
        }
    } else if (op == 0xDDu) {
        switch (m & 0xF8u) {
            case 0xC0: n = "FFREE_STI"; break;  case 0xD0: n = "FST_STI"; break;
            case 0xD8: n = "FSTP_STI"; break;   case 0xE0: n = "FUCOM_STI"; break;
            case 0xE8: n = "FUCOMP_STI"; break; default: break;
        }
    }
    if (n) return n;
    /* Unnamed form: X87_<op>_<modrm> */
    buf[0]='X';buf[1]='8';buf[2]='7';buf[3]='_';
    buf[4]=hex[op>>4];buf[5]=hex[op&15u];buf[6]='_';
    buf[7]=hex[m>>4];buf[8]=hex[m&15u];buf[9]=0;
    return buf;
}

static int cpu_step(void) {
    x86_decoded_t d;
    uint32_t saved_eip = eip;
    uint32_t before_flags = eflags;
    uint32_t before_eax = regs[R_EAX];
    uint32_t before_ecx = regs[R_ECX];
    uint32_t before_edx = regs[R_EDX];
    uint32_t before_ebx = regs[R_EBX];
    uint32_t before_opcode = (uint32_t)MEM8(saved_eip);
    int decoded = x86_decode_instruction(&d);
    if (decoded < 0) {
        last_decoded_map = d.map;
        last_decoded_opcode = d.opcode;
        last_decoded_length = d.cursor - d.start;
        last_decoded_has_modrm = d.has_modrm;
        last_decoded_modrm = d.has_modrm ? d.modrm : 0u;
        x86_copy_semantic_id(last_decoded_semantic_id, "DECODE_FAULT");
        last_dispatch_id = X86_DISPATCH_NONE;
        last_dispatch_count++;
        trace_failure_index = trace_head % X86_TRACE_DEPTH;
        x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                         before_opcode,last_dispatch_id);
        return decoded;
    }

    /*
     * Semantic migration point.
     *
     * The old executor already implements the working v0.8 foundation
     * semantics. Keeping it behind a verified decoder lets us migrate each
     * instruction family independently without maintaining two decoders.
     */
    /* Legacy semantics must begin at the decoded opcode, not at a consumed
     * FS/GS (or other legacy) prefix. The decoder has already accounted for
     * the prefix in d.cursor and d.op_pos. Starting at saved_eip would feed
     * 0x64/0x65 to the legacy switch as if it were an opcode. */
    eip = d.op_pos ? d.op_pos : saved_eip;
    decoded_prefixes = d.prefixes;
    decoded_operand16 = d.operand16;
    last_decoded_map = d.map;
    last_decoded_opcode = d.opcode;
    last_decoded_length = d.cursor - d.start;
    last_decoded_has_modrm = d.has_modrm;
    last_decoded_modrm = d.has_modrm ? d.modrm : 0u;
    x86_copy_semantic_id(last_decoded_semantic_id,
                         (d.entry && d.entry->id) ? d.entry->id : "NONE");

    /* Scalar SSE/SSE2 execution. The decoder has already enforced the
     * F3/F2 prefix constraint, so these semantic IDs are unambiguous. */
    if (d.entry && (x86_id_is(d.entry->id,"MOVSS_XMM_RM32") || x86_id_is(d.entry->id,"MOVSS_RM32_XMM") ||
                    x86_id_is(d.entry->id,"ADDSS_XMM_RM32") || x86_id_is(d.entry->id,"SUBSS_XMM_RM32") ||
                    x86_id_is(d.entry->id,"MULSS_XMM_RM32") || x86_id_is(d.entry->id,"DIVSS_XMM_RM32") ||
                    x86_id_is(d.entry->id,"MOVSD_XMM_RM64") || x86_id_is(d.entry->id,"MOVSD_RM64_XMM") ||
                    x86_id_is(d.entry->id,"ADDSD_XMM_RM64") || x86_id_is(d.entry->id,"SUBSD_XMM_RM64") ||
                    x86_id_is(d.entry->id,"MULSD_XMM_RM64") || x86_id_is(d.entry->id,"DIVSD_XMM_RM64"))) {
        uint8_t m=d.modrm,dst=(uint8_t)((m>>3)&7u),rm=(uint8_t)(m&7u); int mem=((m>>6)!=3); uint32_t ea=0,op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u);
        if(mem&&!modrm_ea(m,&op_ip,&ea)){cpu_error=0x0F00u|d.opcode;return -60;}
        const char *id=d.entry->id;
        if(x86_id_is(id,"MOVSS_XMM_RM32")){uint32_t bits=mem?rd32(ea):xmm_get_u32(rm);xmm_set_u32(dst,bits);if(mem)for(uint32_t i=4;i<16;i++)xmm[dst][i]=0;}
        else if(x86_id_is(id,"MOVSS_RM32_XMM")){uint32_t bits=xmm_get_u32(dst);if(mem)wr32(ea,bits);else xmm_set_u32(rm,bits);}
        else if(x86_id_is(id,"MOVSD_XMM_RM64")){uint64_t bits=mem?((uint64_t)rd32(ea)|((uint64_t)rd32(ea+4u)<<32)):xmm_get_u64(rm);xmm_set_u64(dst,bits);if(mem)for(uint32_t i=8;i<16;i++)xmm[dst][i]=0;}
        else if(x86_id_is(id,"MOVSD_RM64_XMM")){uint64_t bits=xmm_get_u64(dst);if(mem){wr32(ea,(uint32_t)bits);wr32(ea+4u,(uint32_t)(bits>>32));}else{xmm_set_u64(rm,bits);}}
        else if(x86_id_is(id,"ADDSS_XMM_RM32")||x86_id_is(id,"SUBSS_XMM_RM32")||x86_id_is(id,"MULSS_XMM_RM32")||x86_id_is(id,"DIVSS_XMM_RM32")){union{uint32_t u;float f;}s;s.u=mem?rd32(ea):xmm_get_u32(rm);float a=xmm_get_f32(dst),r;if(x86_id_is(id,"ADDSS_XMM_RM32"))r=a+s.f;else if(x86_id_is(id,"SUBSS_XMM_RM32"))r=a-s.f;else if(x86_id_is(id,"MULSS_XMM_RM32"))r=a*s.f;else r=a/s.f;xmm_set_f32(dst,r);}
        else{union{uint64_t u;double f;}s;s.u=mem?((uint64_t)rd32(ea)|((uint64_t)rd32(ea+4u)<<32)):xmm_get_u64(rm);double a=xmm_get_f64(dst),r;if(x86_id_is(id,"ADDSD_XMM_RM64"))r=a+s.f;else if(x86_id_is(id,"SUBSD_XMM_RM64"))r=a-s.f;else if(x86_id_is(id,"MULSD_XMM_RM64"))r=a*s.f;else r=a/s.f;xmm_set_f64(dst,r);}
        eip=d.cursor;last_dispatch_id=X86_DISPATCH_SSE_SCALAR;last_dispatch_count++;x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,before_opcode,last_dispatch_id);return 0;
    }

    /* x87: route every D8..DF escape to the x87 executor by opcode. The
     * previous semantic-ID whitelist silently dropped any form that was not
     * listed (for example DE C8+i), which then fell into the generic
     * "unsupported opcode" path. ModR/M is read after the opcode byte, which
     * is correct even when legacy prefixes precede it. */
    if (d.x87) {
        char x87_buf[12];
        last_decoded_has_modrm=1u;
        last_decoded_modrm=MEM8(d.op_pos+1u);
        x86_copy_semantic_id(last_decoded_semantic_id,
                             x87_semantic_name(d.opcode, last_decoded_modrm, x87_buf));
        uint32_t op_ip = d.op_pos + 1u;
        int xr = cpu_step_x87(d.opcode, &op_ip);
        if (xr < 0) return xr;
        eip = op_ip;
        last_decoded_length = eip - saved_eip;
        last_dispatch_id = X86_DISPATCH_X87;
        last_dispatch_count++;
        x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                         before_opcode,last_dispatch_id);
        return 0;
    }

    /*
     * Refined semantic dispatch:
     * the decoder's instruction ID is authoritative for migrated families.
     * INC is dispatched from the decoded semantic ID rather than re-decoding
     * the raw opcode in the legacy switch.
     */
    if (d.entry && d.entry->id) {
        if (x86_id_is(d.entry->id,"JE_REL8") || x86_id_is(d.entry->id,"JE_REL32") ||
            x86_id_is(d.entry->id,"JNE_REL8") || x86_id_is(d.entry->id,"JNE_REL32") ||
            x86_id_is(d.entry->id,"JB_REL8") || x86_id_is(d.entry->id,"JB_REL32") ||
            x86_id_is(d.entry->id,"JAE_REL8") || x86_id_is(d.entry->id,"JAE_REL32") ||
            x86_id_is(d.entry->id,"JA_REL8") || x86_id_is(d.entry->id,"JA_REL32") ||
            x86_id_is(d.entry->id,"JBE_REL8") || x86_id_is(d.entry->id,"JBE_REL32") ||
            x86_id_is(d.entry->id,"JL_REL8") || x86_id_is(d.entry->id,"JL_REL32") ||
            x86_id_is(d.entry->id,"JGE_REL8") || x86_id_is(d.entry->id,"JGE_REL32") ||
            x86_id_is(d.entry->id,"JLE_REL8") || x86_id_is(d.entry->id,"JLE_REL32") ||
            x86_id_is(d.entry->id,"JG_REL8") || x86_id_is(d.entry->id,"JG_REL32") ||
            x86_id_is(d.entry->id,"JO_REL32") || x86_id_is(d.entry->id,"JNO_REL32") ||
            x86_id_is(d.entry->id,"JS_REL32") || x86_id_is(d.entry->id,"JNS_REL32") ||
            x86_id_is(d.entry->id,"JP_REL32") || x86_id_is(d.entry->id,"JNP_REL32")) {
            int take=0;
            const char *id=d.entry->id;
            if (x86_id_is(id,"JE_REL8") || x86_id_is(id,"JE_REL32")) take=(eflags&ZF)!=0;
            else if (x86_id_is(id,"JNE_REL8") || x86_id_is(id,"JNE_REL32")) take=(eflags&ZF)==0;
            else if (x86_id_is(id,"JB_REL8") || x86_id_is(id,"JB_REL32")) take=(eflags&CF)!=0;
            else if (x86_id_is(id,"JAE_REL8") || x86_id_is(id,"JAE_REL32")) take=(eflags&CF)==0;
            else if (x86_id_is(id,"JA_REL8") || x86_id_is(id,"JA_REL32")) take=(eflags&CF)==0 && (eflags&ZF)==0;
            else if (x86_id_is(id,"JBE_REL8") || x86_id_is(id,"JBE_REL32")) take=(eflags&CF)!=0 || (eflags&ZF)!=0;
            else if (x86_id_is(id,"JL_REL8") || x86_id_is(id,"JL_REL32")) take=((eflags&SF)!=0) != ((eflags&OF)!=0);
            else if (x86_id_is(id,"JGE_REL8") || x86_id_is(id,"JGE_REL32")) take=((eflags&SF)!=0) == ((eflags&OF)!=0);
            else if (x86_id_is(id,"JLE_REL8") || x86_id_is(id,"JLE_REL32")) take=(eflags&ZF)!=0 || (((eflags&SF)!=0) != ((eflags&OF)!=0));
            else if (x86_id_is(id,"JG_REL8") || x86_id_is(id,"JG_REL32")) take=(eflags&ZF)==0 && (((eflags&SF)!=0) == ((eflags&OF)!=0));
            else if (x86_id_is(id,"JO_REL32")) take=(eflags&OF)!=0;
            else if (x86_id_is(id,"JNO_REL32")) take=(eflags&OF)==0;
            else if (x86_id_is(id,"JS_REL32")) take=(eflags&SF)!=0;
            else if (x86_id_is(id,"JNS_REL32")) take=(eflags&SF)==0;
            else if (x86_id_is(id,"JP_REL32")) take=(eflags&PF)!=0;
            else if (x86_id_is(id,"JNP_REL32")) take=(eflags&PF)==0;
            int32_t rel=(d.rel_size==1)?(int8_t)MEM8(d.cursor-1u):(int32_t)rd32(d.cursor-4u);
            eip=take?(uint32_t)((int32_t)d.cursor+rel):d.cursor;
            last_dispatch_id=X86_DISPATCH_JCC;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"CMPXCHG_RM32_R32")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u),ea=0;
            uint8_t m=d.modrm;
            uint32_t acc=regs[R_EAX];
            uint32_t dst=(m>>6)==3u ? regs[m&7u] : 0u;
            if ((m>>6)!=3u) {
                if(!modrm_ea(m,&op_ip,&ea)){cpu_error=0x0FB101u;return -60;}
                dst=rd32(ea);
            }
            uint32_t r=acc-dst;
            set_sub_flags(acc,dst,r);
            if(acc==dst) {
                uint32_t src=regs[(m>>3)&7u];
                if((m>>6)==3u) regs[m&7u]=src;
                else wr32(ea,src);
                eflags|=ZF;
            } else {
                regs[R_EAX]=dst;
                eflags&=~ZF;
            }
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_NONE;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"TEST_RM32_IMM32")) {
            uint32_t op_ip=d.cursor-d.imm_size-d.disp_size-(d.has_sib?1u:0u),ea=0;
            uint32_t value;
            if ((d.modrm>>6)==3) value=regs[d.modrm&7u];
            else { modrm_ea(d.modrm,&op_ip,&ea); value=rd32(ea); }
            uint32_t imm=rd32(d.cursor-4u);
            set_logic_flags(value & imm);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_TEST;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"NEG_RM32") ||
            x86_id_is(d.entry->id,"NOT_RM32") ||
            x86_id_is(d.entry->id,"MUL_RM32") ||
            x86_id_is(d.entry->id,"IMUL_RM32") ||
            x86_id_is(d.entry->id,"DIV_RM32") ||
            x86_id_is(d.entry->id,"IDIV_RM32")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u), ea=0;
            uint8_t sub=(uint8_t)((d.modrm>>3)&7u);
            if ((d.modrm>>6)!=3) modrm_ea(d.modrm,&op_ip,&ea);
            uint32_t v=(d.modrm>>6)==3 ? regs[d.modrm&7u] : rd32(ea);
            uint32_t r=0;
            if (sub==2) {
                r=~v;
                if ((d.modrm>>6)==3) regs[d.modrm&7u]=r; else wr32(ea,r);
            } else if (sub==3) {
                r=0u-v;
                set_sub_flags(0u,v,r);
                if (v) eflags|=CF; else eflags&=~CF;
                if (v==0x80000000u) eflags|=OF; else eflags&=~OF;
                if ((d.modrm>>6)==3) regs[d.modrm&7u]=r; else modrm_write32(d.modrm,&op_ip,r);
            } else if (sub==4) {
                uint64_t p=(uint64_t)regs[R_EAX]*(uint64_t)v;
                regs[R_EAX]=(uint32_t)p; regs[R_EDX]=(uint32_t)(p>>32);
                eflags=(eflags&~(CF|OF))|(((p>>32)!=0)?(CF|OF):0);
            } else if (sub==5) {
                int64_t p=(int64_t)(int32_t)regs[R_EAX]*(int64_t)(int32_t)v;
                uint32_t lo=(uint32_t)p, hi=(uint32_t)((uint64_t)p>>32);
                regs[R_EAX]=lo; regs[R_EDX]=hi;
                eflags=(eflags&~(CF|OF))|((p!=(int64_t)(int32_t)lo)?(CF|OF):0);
            } else if (sub==6) {
                if (v==0) { cpu_error=0xF706u; return -30; }
                uint64_t dividend=((uint64_t)regs[R_EDX]<<32)|regs[R_EAX];
                uint64_t q=dividend/v, rem=dividend%v;
                if(q>0xFFFFFFFFull){cpu_error=0xF707u;return -31;}
                regs[R_EAX]=(uint32_t)q; regs[R_EDX]=(uint32_t)rem;
            } else {
                if (v==0) { cpu_error=0xF708u; return -32; }
                int32_t divisor=(int32_t)v;
                int64_t dividend=((int64_t)(int32_t)regs[R_EDX]<<32)|(uint32_t)regs[R_EAX];
                if(dividend==(-9223372036854775807ll-1ll)&&divisor==-1){cpu_error=0xF709u;return -33;}
                int64_t q=dividend/divisor, rem=dividend%divisor;
                if(q>2147483647ll||q<(-2147483647ll-1ll)){cpu_error=0xF709u;return -33;}
                regs[R_EAX]=(uint32_t)q; regs[R_EDX]=(uint32_t)rem;
            }
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_F7;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"ROL_RM8_IMM8") || x86_id_is(d.entry->id,"ROR_RM8_IMM8") || x86_id_is(d.entry->id,"RCL_RM8_IMM8") || x86_id_is(d.entry->id,"RCR_RM8_IMM8") || x86_id_is(d.entry->id,"SHL_RM8_IMM8") || x86_id_is(d.entry->id,"SHR_RM8_IMM8") || x86_id_is(d.entry->id,"SAL_RM8_IMM8") || x86_id_is(d.entry->id,"SAR_RM8_IMM8") || x86_id_is(d.entry->id,"ROL_RM8_1") || x86_id_is(d.entry->id,"ROR_RM8_1") || x86_id_is(d.entry->id,"RCL_RM8_1") || x86_id_is(d.entry->id,"RCR_RM8_1") || x86_id_is(d.entry->id,"SHL_RM8_1") || x86_id_is(d.entry->id,"SHR_RM8_1") || x86_id_is(d.entry->id,"SAL_RM8_1") || x86_id_is(d.entry->id,"SAR_RM8_1") || x86_id_is(d.entry->id,"ROL_RM8_CL") || x86_id_is(d.entry->id,"ROR_RM8_CL") || x86_id_is(d.entry->id,"RCL_RM8_CL") || x86_id_is(d.entry->id,"RCR_RM8_CL") || x86_id_is(d.entry->id,"SHL_RM8_CL") || x86_id_is(d.entry->id,"SHR_RM8_CL") || x86_id_is(d.entry->id,"SAL_RM8_CL") || x86_id_is(d.entry->id,"SAR_RM8_CL") || x86_id_is(d.entry->id,"ROL_RM32_IMM8") || x86_id_is(d.entry->id,"ROR_RM32_IMM8") || x86_id_is(d.entry->id,"RCL_RM32_IMM8") || x86_id_is(d.entry->id,"RCR_RM32_IMM8") || x86_id_is(d.entry->id,"SHL_RM32_IMM8") || x86_id_is(d.entry->id,"SHR_RM32_IMM8") || x86_id_is(d.entry->id,"SAL_RM32_IMM8") || x86_id_is(d.entry->id,"SAR_RM32_IMM8") || x86_id_is(d.entry->id,"ROL_RM32_1") || x86_id_is(d.entry->id,"ROR_RM32_1") || x86_id_is(d.entry->id,"RCL_RM32_1") || x86_id_is(d.entry->id,"RCR_RM32_1") || x86_id_is(d.entry->id,"SHL_RM32_1") || x86_id_is(d.entry->id,"SHR_RM32_1") || x86_id_is(d.entry->id,"SAR_RM32_1") || x86_id_is(d.entry->id,"SAL_RM32_1") || x86_id_is(d.entry->id,"ROL_RM32_CL") || x86_id_is(d.entry->id,"ROR_RM32_CL") || x86_id_is(d.entry->id,"RCL_RM32_CL") || x86_id_is(d.entry->id,"RCR_RM32_CL") || x86_id_is(d.entry->id,"SHL_RM32_CL") || x86_id_is(d.entry->id,"SHR_RM32_CL") || x86_id_is(d.entry->id,"SAL_RM32_CL") || x86_id_is(d.entry->id,"SAR_RM32_CL") ||
            x86_id_is(d.entry->id,"SHR_RM32_IMM8") ||
            x86_id_is(d.entry->id,"SAR_RM32_IMM8") ||
            x86_id_is(d.entry->id,"ROL_RM32_IMM8") ||
            x86_id_is(d.entry->id,"ROR_RM32_IMM8") ||
            x86_id_is(d.entry->id,"RCL_RM32_IMM8") ||
            x86_id_is(d.entry->id,"RCR_RM32_IMM8") ||
            x86_id_is(d.entry->id,"SHL_RM32_1") ||
            x86_id_is(d.entry->id,"SHR_RM32_1") ||
            x86_id_is(d.entry->id,"SAR_RM32_1") ||
            x86_id_is(d.entry->id,"ROL_RM32_1") ||
            x86_id_is(d.entry->id,"ROR_RM32_1") ||
            x86_id_is(d.entry->id,"RCL_RM32_1") ||
            x86_id_is(d.entry->id,"RCR_RM32_1")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u), ea=0;
            uint8_t sub=(uint8_t)((d.modrm>>3)&7u);
            if ((d.modrm>>6)!=3) modrm_ea(d.modrm,&op_ip,&ea);
            int is8 = (d.entry->id[4]=='8' && d.entry->id[5]=='_');
            uint32_t v=(d.modrm>>6)==3 ? (is8 ? reg8_read(d.modrm&7u) : regs[d.modrm&7u]) : (is8 ? MEM8(ea) : rd32(ea));
            uint32_t count = (d.opcode==0xC0u || d.opcode==0xC1u) ? MEM8(d.cursor-1u) : ((d.opcode==0xD2u || d.opcode==0xD3u) ? (regs[R_ECX]&0xFFu) : 1u);
            uint32_t width = is8 ? 8u : 32u, mask = is8 ? 0xFFu : 0xFFFFFFFFu;
            uint32_t r=v,cf=(eflags&CF)?1u:0u,of=0,of_valid=0;
            count &= is8 ? 7u : 31u;
            if(count){
                uint32_t sign=1u<<(width-1u);
                if(sub==4 || sub==6){r=(v<<count)&mask;cf=(v>>(width-count))&1u;of_valid=count==1;of=((r&sign)?1u:0u)^cf;}
                else if(sub==5){r=v>>count;cf=(v>>(count-1u))&1u;of_valid=count==1;of=(v&sign)?1u:0u;}
                else if(sub==7){r=(uint32_t)((is8 ? (int8_t)v : (int32_t)v)>>count)&mask;cf=(v>>(count-1u))&1u;of_valid=count==1;of=(v&sign)?1u:0u;}
                else if(sub==0){uint32_t n=count%width;if(n){r=((v<<n)|(v>>(width-n)))&mask;cf=r&1u;of_valid=n==1;of=((r&sign)?1u:0u)^cf;}}
                else if(sub==1){uint32_t n=count%width;if(n){r=((v>>n)|(v<<(width-n)))&mask;cf=(r>>(width-1u))&1u;of_valid=n==1;of=((r&sign)?1u:0u)^((r>>(width-2u))&1u);}}
                else if(sub==2){uint32_t n=count%(width+1u);if(n){uint64_t x=((uint64_t)cf<<width)|v;uint64_t fullmask=(1ull<<(width+1u))-1ull;x=((x<<n)|(x>>((width+1u)-n)))&fullmask;r=(uint32_t)x&mask;cf=(uint32_t)((x>>width)&1u);of_valid=n==1;of=((r&sign)?1u:0u)^cf;}}
                else if(sub==3){uint32_t n=count%(width+1u);if(n){uint64_t x=((uint64_t)cf<<width)|v;uint64_t fullmask=(1ull<<(width+1u))-1ull;x=((x>>n)|(x<<((width+1u)-n)))&fullmask;r=(uint32_t)x&mask;cf=(uint32_t)((x>>width)&1u);of_valid=n==1;of=((r&sign)?1u:0u)^((r>>(width-2u))&1u);}}
                else {cpu_error=0xC000u|sub;return -35;}
                if(sub==6) sub=4;
                if(sub>=4) set_shift_flags(r,cf,of_valid,of);
                else set_rotate_flags(r,cf,of_valid,of);
                if((d.modrm>>6)==3) { if(is8) reg8_write(d.modrm&7u,(uint8_t)r); else regs[d.modrm&7u]=r; }
                else { if(is8) wr8(ea,(uint8_t)r); else wr32(ea,r); }
            }
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_GROUP2;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"SUB_RM8_R8") ||
            x86_id_is(d.entry->id,"SUB_R8_RM8")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u),ea=0;
            uint8_t reg=(uint8_t)((d.modrm>>3)&7u),dst,src,r;
            if ((d.modrm>>6)==3) {
                if (x86_id_is(d.entry->id,"SUB_RM8_R8")) {
                    dst=reg8_read(d.modrm&7u); src=reg8_read(reg); r=(uint8_t)(dst-src);
                    reg8_write(d.modrm&7u,r);
                } else {
                    dst=reg8_read(reg); src=reg8_read(d.modrm&7u); r=(uint8_t)(dst-src);
                    reg8_write(reg,r);
                }
            } else {
                if (!modrm_ea(d.modrm,&op_ip,&ea)) { cpu_error=0x2800u|d.opcode; return -37; }
                if (x86_id_is(d.entry->id,"SUB_RM8_R8")) {
                    dst=MEM8(ea); src=reg8_read(reg); r=(uint8_t)(dst-src); wr8(ea,r);
                } else {
                    dst=reg8_read(reg); src=MEM8(ea); r=(uint8_t)(dst-src); reg8_write(reg,r);
                }
            }
            set_sub_flags_width(dst,src,r,8u);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_NONE;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_AL_MOFFS8") ||
            x86_id_is(d.entry->id,"MOV_EAX_MOFFS32") ||
            x86_id_is(d.entry->id,"MOV_MOFFS8_AL") ||
            x86_id_is(d.entry->id,"MOV_MOFFS32_EAX")) {
            uint32_t address=rd32(d.cursor-4u);
            if (x86_id_is(d.entry->id,"MOV_AL_MOFFS8")) {
                reg8_write(0, MEM8(address));
            } else if (x86_id_is(d.entry->id,"MOV_EAX_MOFFS32")) {
                regs[R_EAX]=rd32(address);
            } else if (x86_id_is(d.entry->id,"MOV_MOFFS8_AL")) {
                wr8(address, reg8_read(0));
            } else {
                wr32(address, regs[R_EAX]);
            }
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_NONE;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"XOR_R8_RM8")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u),ea=0;
            uint32_t reg=(uint32_t)((d.modrm>>3)&7u);
            uint8_t a,b,v;
            if ((d.modrm>>6)==3) {
                a=reg8_read(reg); b=reg8_read((uint32_t)(d.modrm&7u));
            } else {
                if(!modrm_ea(d.modrm,&op_ip,&ea)){cpu_error=0x3200u|d.opcode;return -49;}
                a=MEM8(ea); b=reg8_read(reg);
            }
            v=(uint8_t)(a^b);
            if((d.modrm>>6)==3) reg8_write(reg,v); else wr8(ea,v);
            set_logic_flags(v);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_XOR_R8_RM8;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"XOR_EAX_IMM32")) {
            uint32_t b = rd32(d.cursor - 4u);
            uint32_t v = regs[R_EAX] ^ b;
            regs[R_EAX] = v;
            set_logic_flags(v);
            eip = d.cursor;
            last_dispatch_id = X86_DISPATCH_XOR_RM32_IMM32;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"XOR_RM32_IMM32")) {
            uint32_t op_ip = d.cursor - d.imm_size - d.disp_size - (d.has_sib ? 1u : 0u);
            uint32_t a = (d.modrm >> 6) == 3 ? regs[d.modrm & 7u] : modrm_read32(d.modrm, &op_ip);
            uint32_t b = rd32(d.cursor - 4u);
            uint32_t v = a ^ b;
            if ((d.modrm >> 6) == 3) {
                regs[d.modrm & 7u] = v;
            } else {
                uint32_t ea = 0;
                if (!modrm_ea(d.modrm, &op_ip, &ea)) {
                    cpu_error = 0x8180u;
                    return -49;
                }
                wr32(ea, v);
            }
            set_logic_flags(v);
            eip = d.cursor;
            last_dispatch_id = X86_DISPATCH_XOR_RM32_IMM32;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_R32_IMM32") && !decoded_operand16) {
            uint32_t reg=(uint32_t)(d.opcode-0xB8u);
            uint32_t value=rd32(d.cursor-4u);
            regs[reg]=value;
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_R32_IMM32;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"ADD_EAX_IMM32")) {
            uint32_t bits=decoded_operand16?16u:32u;
            uint32_t mask=decoded_operand16?0xFFFFu:0xFFFFFFFFu;
            uint32_t a=regs[R_EAX]&mask;
            uint32_t b=decoded_operand16?(uint32_t)rd16(d.cursor-2u):rd32(d.cursor-4u);
            uint32_t v=(a+b)&mask;
            set_add_flags_width(a,b,v,bits);
            if(decoded_operand16)reg16_write(R_EAX,(uint16_t)v); else regs[R_EAX]=v;
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_ADD_EAX_IMM;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"SUB_EAX_IMM32")) {
            uint32_t bits=decoded_operand16?16u:32u;
            uint32_t mask=decoded_operand16?0xFFFFu:0xFFFFFFFFu;
            uint32_t a=regs[R_EAX]&mask;
            uint32_t b=decoded_operand16?(uint32_t)rd16(d.cursor-2u):rd32(d.cursor-4u);
            uint32_t v=(a-b)&mask;
            set_sub_flags_width(a,b,v,bits);
            if(decoded_operand16)reg16_write(R_EAX,(uint16_t)v); else regs[R_EAX]=v;
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_SUB_EAX_IMM;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"CMP_EAX_IMM32")) {
            uint32_t bits=decoded_operand16?16u:32u;
            uint32_t mask=decoded_operand16?0xFFFFu:0xFFFFFFFFu;
            uint32_t a=regs[R_EAX]&mask;
            uint32_t b=decoded_operand16?(uint32_t)rd16(d.cursor-2u):rd32(d.cursor-4u);
            set_sub_flags_width(a,b,(a-b)&mask,bits);
            eip=d.cursor;
            last_dispatch_id=decoded_operand16?X86_DISPATCH_CMP_R16_IMM16:X86_DISPATCH_CMP_EAX_IMM;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"CMP_R32_RM32") ||
            x86_id_is(d.entry->id,"CMP_RM32_R32")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u);
            uint32_t reg=(uint32_t)((d.modrm>>3)&7u);
            uint32_t a,b;
            if (x86_id_is(d.entry->id,"CMP_R32_RM32")) {
                a=decoded_operand16?reg16_read(reg):regs[reg];
                b=decoded_operand16?modrm_read16(d.modrm,&op_ip):modrm_read32(d.modrm,&op_ip);
            } else {
                a=decoded_operand16?modrm_read16(d.modrm,&op_ip):modrm_read32(d.modrm,&op_ip);
                b=decoded_operand16?reg16_read(reg):regs[reg];
            }
            uint32_t mask=decoded_operand16?0xFFFFu:0xFFFFFFFFu;
            uint32_t bits=decoded_operand16?16u:32u;
            set_sub_flags_width(a&mask,b&mask,(a-b)&mask,bits);
            eip=d.cursor;
            last_dispatch_id=x86_id_is(d.entry->id,"CMP_R32_RM32")?
                X86_DISPATCH_CMP_R32_RM32:X86_DISPATCH_CMP_RM32_R32;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_R32_RM32") ||
            x86_id_is(d.entry->id,"MOV_RM32_R32")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u);
            uint32_t reg=(uint32_t)((d.modrm>>3)&7u);
            if (x86_id_is(d.entry->id,"MOV_R32_RM32")) {
                if (decoded_operand16) reg16_write(reg,modrm_read16(d.modrm,&op_ip));
                else regs[reg]=modrm_read32(d.modrm,&op_ip);
                last_dispatch_id=X86_DISPATCH_MOV_R32_RM32;
            } else {
                if (decoded_operand16) modrm_write16(d.modrm,&op_ip,reg16_read(reg));
                else modrm_write32(d.modrm,&op_ip,regs[reg]);
                last_dispatch_id=X86_DISPATCH_MOV_RM32_R32;
            }
            eip=d.cursor;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_RM16_SREG")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u);
            uint32_t seg=(uint32_t)((d.modrm>>3)&7u);
            if(seg>=6u){cpu_error=0x8C00u|d.modrm;return -48;}
            modrm_write16(d.modrm,&op_ip,x86_seg_selectors[seg]);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_RM16_SREG;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_SREG_RM16")) {
            uint32_t op_ip=d.cursor-d.disp_size-(d.has_sib?1u:0u);
            uint32_t seg=(uint32_t)((d.modrm>>3)&7u);
            uint16_t selector=modrm_read16(d.modrm,&op_ip);
            if(seg==X86_SEG_CS||seg>=6u){cpu_error=0x8E00u|d.modrm;return -48;}
            x86_set_segment_selector(seg,selector);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_SREG_RM16;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_RM8_IMM8")) {
            uint32_t op_ip=d.cursor-d.imm_size-d.disp_size-(d.has_sib?1u:0u);
            uint8_t value=MEM8(d.cursor-1u);
            if ((d.modrm>>6)==3) {
                reg8_write(d.modrm&7u,value);
            } else {
                uint32_t ea=0;
                if (!modrm_ea(d.modrm,&op_ip,&ea)) {
                    cpu_error=0xC601u;
                    return -48;
                }
                wr8(ea,value);
            }
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_R8_IMM8;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_R8_IMM8")) {
            uint32_t reg=(uint32_t)(d.opcode-0xB0u);
            uint8_t value=MEM8(d.cursor-1u);
            reg8_write(reg,value);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_R8_IMM8;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"MOV_R32_IMM32") && decoded_operand16) {
            uint32_t reg=(uint32_t)(d.opcode-0xB8u);
            uint16_t value=rd16(d.cursor-2u);
            reg16_write(reg,value);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_MOV_R16_IMM16;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"CMP_EAX_IMM32") && decoded_operand16) {
            uint32_t a=(uint32_t)reg16_read(R_EAX);
            uint32_t b=(uint32_t)rd16(d.cursor-2u);
            set_sub_flags_width(a,b,(a-b)&0xFFFFu,16u);
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_CMP_R16_IMM16;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
    }
    if (d.entry && d.entry->id) {
        if (x86_id_is(d.entry->id,"HLT")) {
            eip=d.cursor;
            halted=1;
            last_dispatch_id=X86_DISPATCH_HLT;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"CPUID")) {
            /* Deterministic user-mode virtual CPU contract. Leaf 0 exposes
             * a GenuineIntel-compatible vendor string; leaf 1 advertises
             * the scalar x87/SSE2 feature surface currently supported by
             * the XWASM compatibility runtime. */
            uint32_t leaf=regs[R_EAX];
            uint32_t a=0,b=0,c=0,out_d=0;
            const uint32_t feature_edx=0x07000101u; /* FPU,CX8,FXSR,SSE,SSE2 */
            switch(leaf){
                case 0x00000000u:
                    a=0x00000001u;
                    b=0x756E6547u;      /* "Genu" */
                    out_d=0x49656E69u;   /* "ineI" */
                    c=0x6C65746Eu;      /* "ntel" */
                    break;
                case 0x00000001u:
                    a=0x000306A9u;
                    c=0u;
                    out_d=feature_edx;
                    break;
                case 0x80000000u:
                    a=0x80000001u;
                    break;
                case 0x80000001u:
                    /* No extended/64-bit features are exposed. */
                    break;
                default:
                    break;
            }
            regs[R_EAX]=a;
            regs[R_EBX]=b;
            regs[R_ECX]=c;
            regs[R_EDX]=out_d;
            eip=d.cursor;
            last_dispatch_id=X86_DISPATCH_CPUID;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (x86_id_is(d.entry->id,"BT_RM32_R32") ||
            x86_id_is(d.entry->id,"BTS_RM32_R32") ||
            x86_id_is(d.entry->id,"BTR_RM32_R32") ||
            x86_id_is(d.entry->id,"BTC_RM32_R32") ||
            x86_id_is(d.entry->id,"BT_RM32_IMM8") ||
            x86_id_is(d.entry->id,"BTS_RM32_IMM8") ||
            x86_id_is(d.entry->id,"BTR_RM32_IMM8") ||
            x86_id_is(d.entry->id,"BTC_RM32_IMM8")) {
            const char *id=d.entry->id;
            uint32_t op_ip=d.cursor-d.imm_size-d.disp_size-(d.has_sib?1u:0u);
            uint32_t ea=0;
            uint32_t value=0;
            int32_t bit_index;

            if (x86_id_is(id,"BT_RM32_R32") ||
                x86_id_is(id,"BTS_RM32_R32") ||
                x86_id_is(id,"BTR_RM32_R32") ||
                x86_id_is(id,"BTC_RM32_R32")) {
                bit_index=(int32_t)regs[(d.modrm>>3)&7u];
            } else {
                bit_index=(int32_t)(int8_t)MEM8(d.cursor-1u);
            }

            if ((d.modrm>>6)==3) {
                value=regs[d.modrm&7u];
            } else {
                if (modrm_ea(d.modrm,&op_ip,&ea)==0) {
                    cpu_error=0x0FBAu;
                    return -36;
                }
                ea += (uint32_t)(bit_index>>5)*4u;
                value=rd32(ea);
            }

            uint32_t shift=((uint32_t)bit_index)&31u;
            uint32_t old=(value>>shift)&1u;
            eflags=(eflags&~CF)|(old?CF:0);

            if (!x86_id_is(id,"BT_RM32_R32") &&
                !x86_id_is(id,"BT_RM32_IMM8")) {
                if (x86_id_is(id,"BTS_RM32_R32") ||
                    x86_id_is(id,"BTS_RM32_IMM8")) {
                    value|=(1u<<shift);
                } else if (x86_id_is(id,"BTR_RM32_R32") ||
                           x86_id_is(id,"BTR_RM32_IMM8")) {
                    value&=~(1u<<shift);
                } else {
                    value^=(1u<<shift);
                }

                if ((d.modrm>>6)==3) regs[d.modrm&7u]=value;
                else wr32(ea,value);
            }

            eip=d.cursor;
            if (x86_id_is(id,"BT_RM32_R32") || x86_id_is(id,"BT_RM32_IMM8"))
                last_dispatch_id=X86_DISPATCH_BT;
            else if (x86_id_is(id,"BTS_RM32_R32") || x86_id_is(id,"BTS_RM32_IMM8"))
                last_dispatch_id=X86_DISPATCH_BTS;
            else if (x86_id_is(id,"BTR_RM32_R32") || x86_id_is(id,"BTR_RM32_IMM8"))
                last_dispatch_id=X86_DISPATCH_BTR;
            else
                last_dispatch_id=X86_DISPATCH_BTC;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
        if (d.entry->id[0]=='I' && d.entry->id[1]=='N' &&
            d.entry->id[2]=='C' && d.entry->id[3]=='_' &&
            d.entry->id[4]=='R' && d.entry->id[5]=='3' &&
            d.entry->id[6]=='2' && d.entry->id[7]==0) {
            uint32_t reg=(uint32_t)(d.opcode-0x40u);
            uint32_t old_flags=eflags;
            uint32_t a=regs[reg], r=a+1u;
            regs[reg]=r;
            set_add_flags(a,1u,r);
            eflags=(eflags&~CF)|(old_flags&CF);
            eip=saved_eip+1u;
            last_dispatch_id=X86_DISPATCH_INC_R32;
            last_dispatch_count++;
            x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                             before_opcode,last_dispatch_id);
            return 0;
        }
    }

    last_dispatch_id=X86_DISPATCH_NONE;
    legacy_execution_count++;
    int result=cpu_step_legacy();
    x86_trace_record(saved_eip,before_flags,before_eax,before_ecx,before_edx,before_ebx,
                     before_opcode,last_dispatch_id);
    return result;
}