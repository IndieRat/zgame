// XWASM X86 Runtime v0.9
#include <stdint.h>

extern void z_host_log(int32_t level,int32_t ptr,int32_t len);
#define HEAP_BASE_FALLBACK 0x100000u
extern unsigned char __heap_base[];
#define IMAGE_BASE 0x00400000u
#define X86_STRESS_REPORT_BASE 0x00401900u
/* Raw WASM access is now bounded independently of the guest-region layer.  This is
 * the final safety net for the C++/CPU stage: malformed guest pointers must become
 * XWASM memory faults, never browser-level WebAssembly OOB traps. */
static uint32_t eip=0;
static uint32_t x86_mem_faults=0;
static uint32_t cpu_error=0;
static uint32_t x86_last_fault_address=0;
static uint32_t x86_last_fault_size=0;
static uint32_t x86_last_fault_kind=0;
static uint32_t x86_first_fault_eip=0,x86_first_fault_opcode=0,x86_first_fault_modrm=0;
static uint32_t x86_last_fault_eip=0,x86_last_fault_opcode=0,x86_last_fault_modrm=0;
static uint32_t x86_first_fault_count=0;
static uint32_t x86_control_fault_kind=0;
static uint32_t x86_control_fault_eip=0,x86_control_fault_next_eip=0;
static uint32_t x86_control_fault_target=0,x86_control_fault_slot=0;
static uint32_t x86_control_fault_opcode=0,x86_control_fault_modrm=0;
static uint32_t x86_last_stack_fault_esp=0,x86_last_stack_fault_eip=0,x86_last_stack_fault_kind=0;
static uint8_t x86_memory_fault_byte=0;
static uint8_t *x86_wasm_byte_ptr(uint32_t p,uint32_t size,uint32_t kind){
 uint32_t pages=__builtin_wasm_memory_size(0u);
 uint32_t have=pages*65536u;
 uint32_t end=p+size;
 if(end<p||end>have){
  x86_mem_faults++;
  x86_last_fault_address=p;
  x86_last_fault_size=size;
  x86_last_fault_kind=kind;
  x86_last_fault_eip=eip;
  if(x86_first_fault_count==0u)x86_first_fault_eip=eip;
  x86_first_fault_count++;
  cpu_error=0xE100u|kind;
  return &x86_memory_fault_byte;
 }
 return (uint8_t *)(uintptr_t)p;
}
#define MEM8(p) (*x86_wasm_byte_ptr((uint32_t)(p),1u,1u))

/* 32-bit x86 register order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI. */
enum { R_EAX=0,R_ECX,R_EDX,R_EBX,R_ESP,R_EBP,R_ESI,R_EDI };
#define CF 0x00000001u
#define PF 0x00000004u
#define AF 0x00000010u
#define ZF 0x00000040u
#define SF 0x00000080u
#define OF 0x00000800u
#define DF 0x00000400u
#define X86_PREFIX_REPNZ 0x02u
#define X86_PREFIX_REP 0x04u

static uint32_t heap=HEAP_BASE_FALLBACK,image_base=0,image_size=0,entry=0,steps=0,loaded=0;
#define X86_CRT_ATEXIT_MAX 32u
#define X86_CRT_EINVAL 22
#define X86_CRT_ENOMEM 12
#define X86_CRT_EFAULT 14
#define X86_CRT_CALLBACK_SENTINEL 0xF00DC0DEu
#define X86_CRT_CALLBACK_MARKER 0xC2C0FFEEu
#define X86_ENTRY_RETURN_SENTINEL 0xF00DCAFEu
static int32_t crt_errno=0;
static uint32_t crt_last_error=0,crt_started=0,crt_exited=0,crt_exit_code=0;
/* Termination provenance is kept separately from CPU EIP because an exit shim
 * halts the guest after the CALL has advanced EIP to its return site. */
static uint32_t crt_last_termination_kind=0; /* 1=exit, 2=_exit, 3=abort, 4=terminate, 5=_cexit, 6=_c_exit, 7=TerminateProcess, 8=crash report (UnhandledExceptionFilter) */
static uint32_t crt_last_termination_caller=0;
static uint32_t crt_last_termination_return_eip=0;
static uint32_t crt_last_termination_target=0;
static uint32_t crt_last_termination_arg0=0;
static uint32_t crt_last_shim_index=0xFFFFFFFFu;
static uint32_t crt_last_shim_caller=0;
/* Crash-report capture: the guest CRT reached UnhandledExceptionFilter (abort/fastfail/GS failure path). */
static uint32_t crash_hit=0,crash_return_eip=0,crash_nframes=0,crash_arg0=0;
static uint32_t crash_stack[32],crash_frames[16];

static uint32_t crt_last_shim_target=0;
static uint32_t crt_last_shim_arg0=0;
static uint32_t crt_last_shim_argc=0;
static uint32_t crt_atexit_count=0,crt_last_atexit_result=0,crt_last_atexit_ok=0,crt_atexit_running=0;
static uint32_t crt_atexit_callbacks[X86_CRT_ATEXIT_MAX];
/* Forward declarations: shim_call can terminate the guest through the CRT APIs. */
uint32_t x86_crt_startup(void);
uint32_t x86_crt_exit(uint32_t code);
static uint32_t requested_image_base=0,reloc_rva=0,reloc_size=0,import_rva=0,import_size=0;
static uint32_t relocation_needed=0,dll_count=0,import_count=0,load_error=0,last_load_ptr=0,last_load_size=0;
static uint32_t regs[8],eflags=0x00000002u;
#define X86_FLOW_DEPTH 32u
static uint32_t x86_flow_head=0,x86_flow_count=0;
static uint32_t x86_flow_eip[X86_FLOW_DEPTH],x86_flow_esp[X86_FLOW_DEPTH],x86_flow_ebp[X86_FLOW_DEPTH],x86_flow_opcode[X86_FLOW_DEPTH];
static void x86_flow_note(uint32_t at,uint32_t op){uint32_t i=x86_flow_head%X86_FLOW_DEPTH;x86_flow_eip[i]=at;x86_flow_esp[i]=regs[R_ESP];x86_flow_ebp[i]=regs[R_EBP];x86_flow_opcode[i]=op;x86_flow_head=(x86_flow_head+1u)%X86_FLOW_DEPTH;if(x86_flow_count<X86_FLOW_DEPTH)x86_flow_count++;}
/* Minimal x87 state. Values are kept as host doubles for the first compiler-coverage milestone; memory loads/stores still round through IEEE binary32/binary64 formats. */
static double x87_stack[8];
static uint32_t x87_count=0;
/* IA-32 SSE/SSE2 architectural XMM0-XMM7 state. The first SIMD milestone
 * implements scalar operations while retaining all 128 register bits. */
static uint8_t xmm[8][16];
static uint32_t halted=0;
static uint8_t decoded_prefixes=0,decoded_operand16=0;
#define X86_FS_TEB_BASE 0x01E00000u
#define X86_GS_TEB_BASE 0x01E01000u
/* Guest stack: the top is seeded at 0x03F00000 and the stack grows downward.
 * It must be a registered guest region, not merely backed by WASM pages, so
 * CALL/PUSH/POP/RET validation accepts normal compiler-generated epilogues. */
#define X86_STACK_BASE 0x03E00000u
#define X86_STACK_TOP  0x03F00000u
#define X86_STACK_SIZE (X86_STACK_TOP-X86_STACK_BASE)
static uint32_t x86_fs_base=0,x86_gs_base=0;
/* Synthetic Win32-compatible user-mode segment selectors. FS/GS bases are
 * virtualized independently, so selector values only model the observable
 * 16-bit segment-register state used by MOV Sreg instructions. */
#define X86_SEG_ES 0u
#define X86_SEG_CS 1u
#define X86_SEG_SS 2u
#define X86_SEG_DS 3u
#define X86_SEG_FS 4u
#define X86_SEG_GS 5u
static uint16_t x86_seg_selectors[6]={0x0023u,0x001Bu,0x0023u,0x0023u,0x003Bu,0x0053u};
static void x86_reset_segment_selectors(void){
 x86_seg_selectors[0]=0x0023u; x86_seg_selectors[1]=0x001Bu; x86_seg_selectors[2]=0x0023u;
 x86_seg_selectors[3]=0x0023u; x86_seg_selectors[4]=0x003Bu; x86_seg_selectors[5]=0x0053u;
 x86_fs_base=0u; x86_gs_base=0u;
}
static void x86_set_segment_selector(uint32_t seg,uint16_t sel){
 if(seg>=6u)return;
 x86_seg_selectors[seg]=sel;
 if(seg==X86_SEG_FS)x86_fs_base=(sel==0x003Bu)?X86_FS_TEB_BASE:0u;
 else if(seg==X86_SEG_GS)x86_gs_base=(sel==0x0053u)?X86_GS_TEB_BASE:0u;
}

static uint32_t last_decoded_map=0,last_decoded_opcode=0,last_decoded_length=0;
static uint32_t last_decoded_modrm=0,last_decoded_has_modrm=0;
static uint32_t last_dispatch_id=0,last_dispatch_count=0,legacy_execution_count=0;
static uint32_t last_indirect_slot=0,last_indirect_target=0;
#define X86_SEMANTIC_ID_MAX 64u
static char last_decoded_semantic_id[X86_SEMANTIC_ID_MAX];
#define X86_TRACE_DEPTH 256u
static uint32_t trace_eip[X86_TRACE_DEPTH],trace_next_eip[X86_TRACE_DEPTH];
static uint32_t trace_opcode[X86_TRACE_DEPTH],trace_flags[X86_TRACE_DEPTH];
static uint32_t trace_eax[X86_TRACE_DEPTH],trace_ecx[X86_TRACE_DEPTH];
static uint32_t trace_ebx[X86_TRACE_DEPTH],trace_edx[X86_TRACE_DEPTH];
/* Each trace entry keeps both sides of the instruction boundary.  The legacy
 * trace_* register fields are the pre-state; trace_post_* are the state after
 * execution.  This makes dataflow faults attributable without guessing from
 * the next instruction's pre-state. */
static uint32_t trace_post_eax[X86_TRACE_DEPTH],trace_post_ecx[X86_TRACE_DEPTH];
static uint32_t trace_post_ebx[X86_TRACE_DEPTH],trace_post_edx[X86_TRACE_DEPTH];
static uint32_t trace_post_flags[X86_TRACE_DEPTH];
static uint32_t trace_dispatch[X86_TRACE_DEPTH];
static char trace_semantic_id[X86_TRACE_DEPTH][X86_SEMANTIC_ID_MAX];
static uint32_t trace_post_esp[X86_TRACE_DEPTH],trace_post_ebp[X86_TRACE_DEPTH];
static uint32_t trace_count=0,trace_head=0,trace_failure_index=0;
static int modrm_ea(uint8_t m,uint32_t *ip,uint32_t *ea);
static int cpu_step_x87(uint8_t op,uint32_t *ip);
static void x86_gdr_note_call(uint32_t slot);
static int x86_gdr_rebind_slot(uint32_t slot);
static uint32_t xmm_get_u32(uint8_t r){return (uint32_t)xmm[r][0]|((uint32_t)xmm[r][1]<<8)|((uint32_t)xmm[r][2]<<16)|((uint32_t)xmm[r][3]<<24);}
static void xmm_set_u32(uint8_t r,uint32_t v){xmm[r][0]=(uint8_t)v;xmm[r][1]=(uint8_t)(v>>8);xmm[r][2]=(uint8_t)(v>>16);xmm[r][3]=(uint8_t)(v>>24);}
static uint64_t xmm_get_u64(uint8_t r){uint64_t lo=xmm_get_u32(r);uint32_t hi=(uint32_t)xmm[r][4]|((uint32_t)xmm[r][5]<<8)|((uint32_t)xmm[r][6]<<16)|((uint32_t)xmm[r][7]<<24);return lo|((uint64_t)hi<<32);}
static void xmm_set_u64(uint8_t r,uint64_t v){xmm_set_u32(r,(uint32_t)v);uint32_t hi=(uint32_t)(v>>32);xmm[r][4]=(uint8_t)hi;xmm[r][5]=(uint8_t)(hi>>8);xmm[r][6]=(uint8_t)(hi>>16);xmm[r][7]=(uint8_t)(hi>>24);}
static float xmm_get_f32(uint8_t r){union{uint32_t u;float f;}v;v.u=xmm_get_u32(r);return v.f;}
static void xmm_set_f32(uint8_t r,float v){union{uint32_t u;float f;}x;x.f=v;xmm_set_u32(r,x.u);}
static double xmm_get_f64(uint8_t r){union{uint64_t u;double f;}v;v.u=xmm_get_u64(r);return v.f;}
static void xmm_set_f64(uint8_t r,double v){union{uint64_t u;double f;}x;x.f=v;xmm_set_u64(r,x.u);}
static void xmm_reset(void){for(uint32_t r=0;r<8u;r++)for(uint32_t b=0;b<16u;b++)xmm[r][b]=0;}
static void x86_copy_semantic_id(char *dst,const char *src){uint32_t i=0;if(!src)src="NONE";for(;i+1u<X86_SEMANTIC_ID_MAX&&src[i];++i)dst[i]=src[i];dst[i]=0;}
static int x86_profile_str_eq(const char *a,const char *b){
 if(!a)a="NONE"; if(!b)b="NONE";
 while(*a&&*b){if(*a++!=*b++)return 0;} return *a==0&&*b==0;
}
#define X86_PROFILE_SLOTS 1024u
typedef struct {
 uint32_t used,map,opcode,modrm,has_modrm,dispatch,count,first_eip,last_eip,min_length,max_length;
 char semantic[X86_SEMANTIC_ID_MAX];
} x86_profile_entry_t;
static x86_profile_entry_t x86_profile[X86_PROFILE_SLOTS];
static uint32_t x86_profile_count=0,x86_profile_enabled=1;
static uint32_t x86_profile_hash(uint32_t map,uint32_t opcode,uint32_t modrm,uint32_t has_modrm,const char *id){
 uint32_t h=2166136261u;
 h=(h^map)*16777619u;h=(h^opcode)*16777619u;h=(h^modrm)*16777619u;h=(h^has_modrm)*16777619u;
 if(!id)id="NONE"; for(uint32_t i=0;id[i];i++)h=(h^(uint8_t)id[i])*16777619u;
 return h;
}
static void x86_profile_clear(void){
 for(uint32_t i=0;i<X86_PROFILE_SLOTS;i++)x86_profile[i]=(x86_profile_entry_t){0};
 x86_profile_count=0;
}
static void x86_profile_record(uint32_t ip){
 if(!x86_profile_enabled)return;
 const char *id=last_decoded_semantic_id[0]?last_decoded_semantic_id:"NONE";
 uint32_t h=x86_profile_hash(last_decoded_map,last_decoded_opcode,last_decoded_modrm,last_decoded_has_modrm,id);
 for(uint32_t probe=0;probe<X86_PROFILE_SLOTS;probe++){
  uint32_t i=(h+probe)%X86_PROFILE_SLOTS; x86_profile_entry_t *p=&x86_profile[i];
  if(!p->used){
   p->used=1;p->map=last_decoded_map;p->opcode=last_decoded_opcode;p->modrm=last_decoded_modrm;
   p->has_modrm=last_decoded_has_modrm;p->dispatch=last_dispatch_id;p->count=1;
   p->first_eip=ip;p->last_eip=ip;p->min_length=last_decoded_length;p->max_length=last_decoded_length;
   x86_copy_semantic_id(p->semantic,id);x86_profile_count++;return;
  }
  if(p->map==last_decoded_map&&p->opcode==last_decoded_opcode&&p->modrm==last_decoded_modrm&&
     p->has_modrm==last_decoded_has_modrm&&x86_profile_str_eq(p->semantic,id)){
   p->count++;p->last_eip=ip;
   if(last_decoded_length<p->min_length)p->min_length=last_decoded_length;
   if(last_decoded_length>p->max_length)p->max_length=last_decoded_length;
   return;
  }
 }
}

/* ---- Stack diagnostics: shadow call stack and ESP-jump watch ---------------------------------
 * The shadow stack mirrors CALL/RET. A RET whose target is not the return address of any open
 * call ("unmatched"), or whose ESP differs from the one right after the matching CALL's push
 * ("mismatch"), is recorded with the callee that was running. The ESP watch records the first
 * instructions after which ESP moved by more than 64 KiB, with a snapshot of the preceding trace. */
#define X86_SHADOW_DEPTH 1024u
#define X86_ESPW_EVENTS 4u
#define X86_ESPW_SNAP 24u
static uint32_t sh_ret[X86_SHADOW_DEPTH],sh_esp[X86_SHADOW_DEPTH],sh_callee[X86_SHADOW_DEPTH],sh_site[X86_SHADOW_DEPTH];
static uint32_t sh_top=0,sh_overflow=0,sh_calls=0,sh_rets=0;
static uint32_t sh_mm_count=0,sh_um_count=0;
static uint32_t sh_mm[8],sh_um[8],sh_mm_last[8],sh_um_last[8]; /* ret_eip,target,esp,expected esp,callee,site,steps,depth */
static uint32_t espw_count=0,espw_prev=0;
static uint32_t espw_ev[X86_ESPW_EVENTS][6]; /* eip,esp before,esp after,opcode,steps,sh_top */
static uint32_t espw_snap_eip[X86_ESPW_EVENTS][X86_ESPW_SNAP],espw_snap_op[X86_ESPW_EVENTS][X86_ESPW_SNAP],espw_snap_esp[X86_ESPW_EVENTS][X86_ESPW_SNAP],espw_snap_ebp[X86_ESPW_EVENTS][X86_ESPW_SNAP];
static void x86_shadow_reset(void){sh_top=0;sh_overflow=0;sh_calls=0;sh_rets=0;sh_mm_count=0;sh_um_count=0;espw_count=0;espw_prev=0;for(uint32_t i=0;i<8u;i++){sh_mm[i]=sh_um[i]=sh_mm_last[i]=sh_um_last[i]=0;}}
static void x86_shadow_call(uint32_t site,uint32_t ret_addr,uint32_t callee){
 sh_calls++;
 if(sh_top>=X86_SHADOW_DEPTH){sh_overflow++;return;}
 sh_ret[sh_top]=ret_addr;sh_esp[sh_top]=regs[R_ESP];sh_callee[sh_top]=callee;sh_site[sh_top]=site;sh_top++;
}
static void x86_shadow_drop(void){if(sh_top)sh_top--;}
static void x86_shadow_note(uint32_t*first,uint32_t*last,uint32_t*count,uint32_t ret_eip,uint32_t target,uint32_t esp,uint32_t expect,uint32_t callee,uint32_t site){
 uint32_t v[8]={ret_eip,target,esp,expect,callee,site,steps,sh_top};
 if(*count==0)for(uint32_t i=0;i<8u;i++)first[i]=v[i];
 for(uint32_t i=0;i<8u;i++)last[i]=v[i];
 (*count)++;
}
/* esp_at_ret points at the return address (before it is popped). */
static void x86_shadow_ret(uint32_t ret_eip,uint32_t target,uint32_t esp_at_ret){
 sh_rets++;
 for(int32_t j=(int32_t)sh_top-1;j>=0;j--)if(sh_ret[j]==target){
  if(esp_at_ret!=sh_esp[j])x86_shadow_note(sh_mm,sh_mm_last,&sh_mm_count,ret_eip,target,esp_at_ret,sh_esp[j],sh_callee[j],sh_site[j]);
  sh_top=(uint32_t)j;return;
 }
 x86_shadow_note(sh_um,sh_um_last,&sh_um_count,ret_eip,target,esp_at_ret,0,sh_top?sh_callee[sh_top-1u]:0,sh_top?sh_site[sh_top-1u]:0);
}
static void x86_espw_event(uint32_t eip_before,uint32_t from,uint32_t to){
 if(espw_count<X86_ESPW_EVENTS){
  uint32_t k=espw_count;
  espw_ev[k][0]=eip_before;espw_ev[k][1]=from;espw_ev[k][2]=to;espw_ev[k][3]=trace_count?trace_opcode[(trace_head+X86_TRACE_DEPTH-1u)%X86_TRACE_DEPTH]:0;espw_ev[k][4]=steps;espw_ev[k][5]=sh_top;
  uint32_t n=trace_count<X86_ESPW_SNAP?trace_count:X86_ESPW_SNAP;
  for(uint32_t i=0;i<X86_ESPW_SNAP;i++){
   if(i<n){uint32_t idx=(trace_head+X86_TRACE_DEPTH-n+i)%X86_TRACE_DEPTH;espw_snap_eip[k][i]=trace_eip[idx];espw_snap_op[k][i]=trace_opcode[idx];espw_snap_esp[k][i]=trace_post_esp[idx];espw_snap_ebp[k][i]=trace_post_ebp[idx];}
   else{espw_snap_eip[k][i]=espw_snap_op[k][i]=espw_snap_esp[k][i]=espw_snap_ebp[k][i]=0;}
  }
 }
 espw_count++;
}
static void x86_trace_reset(void){trace_count=0;trace_head=0;trace_failure_index=0;last_decoded_semantic_id[0]=0;x86_shadow_reset();}
static void x86_trace_record(uint32_t before_eip,uint32_t before_flags,uint32_t before_eax,uint32_t before_ecx,uint32_t before_edx,uint32_t before_ebx,uint32_t before_opcode,uint32_t dispatch){
 uint32_t i=trace_head%X86_TRACE_DEPTH;
 trace_eip[i]=before_eip; trace_next_eip[i]=eip; trace_opcode[i]=before_opcode;
 trace_flags[i]=before_flags; trace_eax[i]=before_eax; trace_ecx[i]=before_ecx;
 trace_edx[i]=before_edx; trace_ebx[i]=before_ebx; trace_dispatch[i]=dispatch;
 trace_post_eax[i]=regs[R_EAX]; trace_post_ecx[i]=regs[R_ECX];
 trace_post_edx[i]=regs[R_EDX]; trace_post_ebx[i]=regs[R_EBX];
 trace_post_flags[i]=eflags;
 trace_post_esp[i]=regs[R_ESP]; trace_post_ebp[i]=regs[R_EBP];
 x86_copy_semantic_id(trace_semantic_id[i],last_decoded_semantic_id);
 trace_head=(trace_head+1u)%X86_TRACE_DEPTH; if(trace_count<X86_TRACE_DEPTH)trace_count++;
 x86_profile_record(before_eip);
 if(regs[R_EAX]==0xDEADC0DEu && before_eax!=0xDEADC0DEu) trace_failure_index=i+1u;
}
enum { X86_DISPATCH_NONE=0, X86_DISPATCH_INC_R32=1, X86_DISPATCH_DEC_R32=2, X86_DISPATCH_RCR=3, X86_DISPATCH_MOV_R8_IMM8=4, X86_DISPATCH_MOV_R16_IMM16=5, X86_DISPATCH_CMP_R16_IMM16=6, X86_DISPATCH_MOV_R32_IMM32=7, X86_DISPATCH_ADD_EAX_IMM=8, X86_DISPATCH_SUB_EAX_IMM=9, X86_DISPATCH_CMP_EAX_IMM=10, X86_DISPATCH_MOV_R32_RM32=11, X86_DISPATCH_MOV_RM32_R32=12, X86_DISPATCH_CMP_R32_RM32=13, X86_DISPATCH_CMP_RM32_R32=14, X86_DISPATCH_JCC=15, X86_DISPATCH_GROUP2=16, X86_DISPATCH_F7=17, X86_DISPATCH_HLT=18, X86_DISPATCH_BT=19, X86_DISPATCH_BTS=20, X86_DISPATCH_BTR=21, X86_DISPATCH_BTC=22, X86_DISPATCH_X87=23, X86_DISPATCH_XOR_RM32_IMM32=24, X86_DISPATCH_SSE_SCALAR=25, X86_DISPATCH_CPUID=26, X86_DISPATCH_TEST=27, X86_DISPATCH_XOR_R8_RM8=28, X86_DISPATCH_MOV_RM16_SREG=29, X86_DISPATCH_MOV_SREG_RM16=30, X86_DISPATCH_MOVUPS=31 };

/* v0.4 guest memory/import foundation. The guest-visible address space is
 * intentionally separate from the WASM allocator used for diagnostics. */
#define GUEST_HEAP_BASE 0x00800000u
#define GUEST_HEAP_LIMIT 0x01F00000u
#define API_BASE 0x70000000u
/* Unresolved-import trap range: one 4-byte slot per GDR record. A call/jmp into it stops the CPU with the exact import named. */
#define API_UNRESOLVED_BASE (API_BASE+0x00F00000u)
#define API_UNRESOLVED_ORDINAL (API_UNRESOLVED_BASE+0x0000FFF0u)
#define API_UNRESOLVED_END (API_UNRESOLVED_BASE+0x00010000u)
#define API_GETTICKCOUNT (API_BASE+0x00001000u)
#define API_XWASM_LOG (API_BASE+0x00002000u)
#define API_VIRTUALALLOC (API_BASE+0x00003000u)
#define API_VIRTUALFREE (API_BASE+0x00003004u)
#define API_USER32_CREATEWINDOWEXA (API_BASE+0x00004000u)
#define API_USER32_SHOWWINDOW (API_BASE+0x00004004u)
#define API_USER32_GETDC (API_BASE+0x00004008u)
#define API_USER32_RELEASEDC (API_BASE+0x0000400Cu)
#define API_GDI32_SETPIXEL (API_BASE+0x00005000u)
#define API_GDI32_RECTANGLE (API_BASE+0x00005004u)
#define API_GDI32_SWAPBUFFERS (API_BASE+0x00005008u)
#define API_GDI32_CHOOSEPIXELFORMAT (API_BASE+0x0000500Cu)
#define API_GDI32_SETPIXELFORMAT (API_BASE+0x00005010u)
#define API_OPENGL32_WGLCREATECONTEXT (API_BASE+0x0000A000u)
#define API_OPENGL32_WGLDELETECONTEXT (API_BASE+0x0000A004u)
#define API_OPENGL32_WGLMAKECURRENT (API_BASE+0x0000A008u)
#define API_OPENGL32_WGLGETCURRENTCONTEXT (API_BASE+0x0000A00Cu)
#define API_OPENGL32_GLCLEARCOLOR (API_BASE+0x0000A010u)
#define API_OPENGL32_GLCLEAR (API_BASE+0x0000A014u)
#define API_OPENGL32_GLVIEWPORT (API_BASE+0x0000A018u)
#define API_OPENGL32_GLBEGIN (API_BASE+0x0000A01Cu)
#define API_OPENGL32_GLEND (API_BASE+0x0000A020u)
#define API_OPENGL32_GLCOLOR3F (API_BASE+0x0000A024u)
#define API_OPENGL32_GLCOLOR4F (API_BASE+0x0000A028u)
#define API_OPENGL32_GLVERTEX2F (API_BASE+0x0000A02Cu)
#define API_OPENGL32_GLVERTEX3F (API_BASE+0x0000A030u)
#define API_OPENGL32_GLFLUSH (API_BASE+0x0000A034u)
#define API_OPENGL32_GLFINISH (API_BASE+0x0000A038u)
#define API_OPENGL32_GLGETSTRING (API_BASE+0x0000A03Cu)
#define API_OPENGL32_GLENABLE (API_BASE+0x0000A040u)
#define API_OPENGL32_GLDISABLE (API_BASE+0x0000A044u)
#define API_OPENGL32_GLBLENDFUNC (API_BASE+0x0000A048u)
#define API_OPENGL32_GLDEPTHFUNC (API_BASE+0x0000A04Cu)
#define API_OPENGL32_GLDEPTHMASK (API_BASE+0x0000A050u)
#define API_OPENGL32_GLLINEWIDTH (API_BASE+0x0000A054u)
#define API_OPENGL32_GLPOINTSIZE (API_BASE+0x0000A058u)
#define API_OPENGL32_GLTEXCOORD2F (API_BASE+0x0000A05Cu)
#define API_OPENGL32_GLNORMAL3F (API_BASE+0x0000A060u)
#define API_OPENGL32_GLMATRIXMODE (API_BASE+0x0000A064u)
#define API_OPENGL32_GLLOADIDENTITY (API_BASE+0x0000A068u)
#define API_OPENGL32_GL_PUSHMATRIX (API_BASE+0x0000A06Cu)
#define API_OPENGL32_GL_POPMATRIX (API_BASE+0x0000A070u)
#define API_OPENGL32_GLTRANSLATEF (API_BASE+0x0000A074u)
#define API_OPENGL32_GLSCALEF (API_BASE+0x0000A078u)
#define API_OPENGL32_GLROTATEF (API_BASE+0x0000A07Cu)
#define API_OPENGL32_WGLSHARELISTS (API_BASE+0x0000A080u)
#define API_OPENGL32_WGLGETPROCADDRESS (API_BASE+0x0000A084u)
#define API_USER32_GETMESSAGEA (API_BASE+0x00006000u)
#define API_USER32_PEEKMESSAGEA (API_BASE+0x00006004u)
#define API_USER32_TRANSLATEMESSAGE (API_BASE+0x00006008u)
#define API_USER32_DISPATCHMESSAGEA (API_BASE+0x0000600Cu)
#define API_USER32_DEFWINDOWPROCA (API_BASE+0x00006010u)
#define API_USER32_POSTQUITMESSAGE (API_BASE+0x00006014u)
#define API_USER32_GETCLIENTRECT (API_BASE+0x00006018u)
#define API_USER32_INVALIDATERECT (API_BASE+0x0000601Cu)
#define API_USER32_UPDATEWINDOW (API_BASE+0x00006020u)
#define API_KERNEL32_BEEP (API_BASE+0x00007000u)
#define API_KERNEL32_CREATEFILEA (API_BASE+0x00008000u)
#define API_KERNEL32_READFILE (API_BASE+0x00008004u)
#define API_KERNEL32_WRITEFILE (API_BASE+0x00008008u)
#define API_KERNEL32_CLOSEHANDLE (API_BASE+0x0000800Cu)
#define API_KERNEL32_SETFILEPOINTER (API_BASE+0x00008010u)
#define API_KERNEL32_GETFILESIZE (API_BASE+0x00008014u)
#define API_KERNEL32_REGOPENKEYEXA (API_BASE+0x00008018u)
#define API_KERNEL32_REGCREATEKEYEXA (API_BASE+0x0000801Cu)
#define API_KERNEL32_REGQUERYVALUEEXA (API_BASE+0x00008020u)
#define API_KERNEL32_REGSETVALUEEXA (API_BASE+0x00008024u)
#define API_KERNEL32_REGCLOSEKEY (API_BASE+0x00008028u)
#define API_KERNEL32_REGDELETEVALUEA (API_BASE+0x0000802Cu)
#define API_KERNEL32_GETLASTERROR (API_BASE+0x00008030u)
#define API_KERNEL32_SETLASTERROR (API_BASE+0x00008034u)
#define API_C5_MALLOC (API_BASE+0x00010000u)
#define API_C5_FREE (API_BASE+0x00010004u)
#define API_C5_STRLEN (API_BASE+0x00010008u)
#define API_C5_FS_MOUNT (API_BASE+0x0001000Cu)
#define API_C5_FS_OPEN (API_BASE+0x00010010u)
#define API_C5_FS_READ (API_BASE+0x00010014u)
#define API_C5_FS_CLOSE (API_BASE+0x00010018u)
#define API_C5_REG_CREATE (API_BASE+0x0001001Cu)
#define API_C5_REG_SET (API_BASE+0x00010020u)
#define API_C5_REG_CLOSE (API_BASE+0x00010024u)
#define API_C5_REG_HKEY_CURRENT_USER 0x80000001u
extern int32_t z_host_input_poll(int32_t msg_ptr,int32_t remove);
extern void z_host_input_quit(void);
extern void z_host_audio_beep(int32_t frequency,int32_t duration_ms);
extern void z_host_gfx_create(int32_t width,int32_t height);
extern void z_host_gfx_clear(int32_t color);
extern void z_host_gfx_pixel(int32_t x,int32_t y,int32_t color);
extern void z_host_gfx_rect(int32_t left,int32_t top,int32_t right,int32_t bottom,int32_t color);
extern void z_host_gfx_present(void);

/* v0.9 memory allocator state must precede the region helpers that use it. */
static uint32_t guest_vm=0x02000000u;
static uint32_t guest_vm_limit=0x0F000000u;
static uint32_t last_virtual_alloc=0,last_virtual_alloc_size=0,virtual_free_count=0;
static uint32_t al4(uint32_t x);
static uint32_t rd32(uint32_t p);
static void wr32(uint32_t p,uint32_t v);
static void wr16(uint32_t p,uint16_t v);
static void wr8(uint32_t p,uint8_t v);
/* v0.9 memory subsystem: explicit guest regions plus checked bulk-memory helpers.
 * The current instruction core still uses its established little-endian accessors;
 * these APIs establish the common memory contract that future CPU/CRT code can use
 * without exposing raw WASM addresses to guest-facing allocation code. */
#define X86_MEM_REGION_MAX 64u
#define X86_MEM_READ  0x01u
#define X86_MEM_WRITE 0x02u
#define X86_MEM_EXEC  0x04u

typedef struct {
 uint32_t base;
 uint32_t size;
 uint32_t flags;
 uint32_t kind;
 uint32_t active;
} x86_mem_region_t;

static x86_mem_region_t x86_mem_regions[X86_MEM_REGION_MAX];
static uint32_t x86_mem_region_count=0;

static void x86_mem_reset(void){
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)x86_mem_regions[i].active=0;
 x86_mem_region_count=0; x86_mem_faults=0;
}
static int x86_mem_region_add(uint32_t base,uint32_t size,uint32_t flags,uint32_t kind){
 if(!size||base+size<base)return 0;
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(!x86_mem_regions[i].active){
  x86_mem_regions[i].base=base; x86_mem_regions[i].size=size;
  x86_mem_regions[i].flags=flags; x86_mem_regions[i].kind=kind; x86_mem_regions[i].active=1;
  x86_mem_region_count++; return 1;
 }
 return 0;
}
static int x86_mem_region_find(uint32_t p,uint32_t n,uint32_t need){
 if(n==0)return 1;
 uint32_t end=p+n; if(end<p)return 0;
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active){
  uint32_t r_end=x86_mem_regions[i].base+x86_mem_regions[i].size;
  if(p>=x86_mem_regions[i].base&&end<=r_end&&(x86_mem_regions[i].flags&need))return 1;
 }
 return 0;
}
static int x86_mem_ensure_wasm(uint32_t end){
 uint32_t pages=__builtin_wasm_memory_size(0u);
 uint32_t have=pages*65536u;
 if(end<=have)return 1;
 uint32_t want=(end+65535u)/65536u;
 if(want>4096u)return 0;
 uint32_t grow=want-pages;
 if(grow==0)return 1;
 return __builtin_wasm_memory_grow(0u,grow)>=0;
}
static uint32_t x86_mem_alloc_region(uint32_t size,uint32_t flags,uint32_t kind){
 uint32_t a=al4(guest_vm),n=al4(size),end;
 if(!size)return 0;
 if(!n)return 0;
 for(uint32_t pass=0;pass<X86_MEM_REGION_MAX;pass++){
  end=a+n;
  if(end<a||end>guest_vm_limit)return 0;
  int overlap=0;
  for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active){
   uint32_t r_end=x86_mem_regions[i].base+x86_mem_regions[i].size;
   if(a<r_end&&end>x86_mem_regions[i].base){
    a=al4(r_end);
    overlap=1;
    break;
   }
  }
  if(!overlap)break;
 }
 end=a+n;
 if(end<a||end>guest_vm_limit||!x86_mem_ensure_wasm(end))return 0;
 if(!x86_mem_region_add(a,n,flags,kind))return 0;
 guest_vm=end; last_virtual_alloc=a; last_virtual_alloc_size=n; return a;
}
static int x86_crt_find_alloc(uint32_t address,uint32_t *size){
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==address&&x86_mem_regions[i].kind==5u){
  if(size)*size=x86_mem_regions[i].size; return 1;
 }
 return 0;
}
static uint32_t x86_crt_malloc_impl(uint32_t size){
 return x86_mem_alloc_region(size,X86_MEM_READ|X86_MEM_WRITE,5u);
}
static uint32_t x86_crt_calloc_impl(uint32_t count,uint32_t size){
 if(count&&size>0xFFFFFFFFu/count)return 0;
 uint32_t total=count*size;
 if(!total)return 0;
 uint32_t p=x86_crt_malloc_impl(total);
 if(!p)return 0;
 for(uint32_t i=0;i<total;i++)wr8(p+i,0);
 return p;
}
static uint32_t x86_crt_free_impl(uint32_t address){
 if(!address)return 1;
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==address&&x86_mem_regions[i].kind==5u){
  x86_mem_regions[i].active=0; x86_mem_region_count--; return 1;
 }
 x86_mem_faults++; return 0;
}
static uint32_t x86_crt_realloc_impl(uint32_t address,uint32_t size){
 if(!address)return x86_crt_malloc_impl(size);
 if(!size){x86_crt_free_impl(address);return 0;}
 uint32_t old_size=0;
 if(!x86_crt_find_alloc(address,&old_size)){x86_mem_faults++;return 0;}
 if(size<=old_size){
  for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==address&&x86_mem_regions[i].kind==5u){
   x86_mem_regions[i].size=al4(size); return address;
  }
 }
 uint32_t p=x86_crt_malloc_impl(size);
 if(!p)return 0;
 uint32_t n=old_size<size?old_size:size;
 for(uint32_t i=0;i<n;i++)wr8(p+i,MEM8(address+i));
 x86_crt_free_impl(address);
 return p;
}

static uint32_t x86_mem_free_region(uint32_t address){
 for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==address&&x86_mem_regions[i].kind==2u){
  x86_mem_regions[i].active=0; x86_mem_region_count--; virtual_free_count++; return 1;
 }
 return 0;
}
static void x86_mem_register_image(void){
 x86_mem_region_add(image_base,image_size,X86_MEM_READ|X86_MEM_EXEC|X86_MEM_WRITE,1u);
 x86_mem_region_add(GUEST_HEAP_BASE,GUEST_HEAP_LIMIT-GUEST_HEAP_BASE,X86_MEM_READ|X86_MEM_WRITE,3u);
 x86_mem_region_add(0x03E00000u,0x00100000u,X86_MEM_READ|X86_MEM_WRITE,4u);
}

#define X86_FS_MAX_FILES 32u
#define X86_FS_MAX_HANDLES 32u
#define X86_FS_MAX_PATH 256u
#define X86_FS_HANDLE_BASE 0x1000u
#define X86_FS_ACCESS_READ  0x01u
#define X86_FS_ACCESS_WRITE 0x02u
#define X86_FS_OPEN_CREATE  0x04u
#define X86_FS_OPEN_TRUNCATE 0x08u

typedef struct {
 uint32_t used;
 uint32_t data;
 uint32_t size;
 uint32_t capacity;
 char path[X86_FS_MAX_PATH];
} x86_fs_file_t;
typedef struct {
 uint32_t used;
 uint32_t file;
 uint32_t pos;
 uint32_t access;
} x86_fs_handle_t;
static x86_fs_file_t x86_fs_files[X86_FS_MAX_FILES];
static x86_fs_handle_t x86_fs_handles[X86_FS_MAX_HANDLES];
static uint32_t x86_fs_last_error=0;

static void x86_fs_reset(void){
 for(uint32_t i=0;i<X86_FS_MAX_FILES;i++){x86_fs_files[i].used=0;x86_fs_files[i].data=0;x86_fs_files[i].size=0;x86_fs_files[i].capacity=0;x86_fs_files[i].path[0]=0;}
 for(uint32_t i=0;i<X86_FS_MAX_HANDLES;i++)x86_fs_handles[i].used=0;
 x86_fs_last_error=0;
}
static int x86_fs_guest_string(uint32_t ptr,char *out,uint32_t cap){
 if(!ptr||cap<2u)return 0;
 for(uint32_t i=0;i+1u<cap;i++){
  if(!x86_mem_region_find(ptr+i,1u,X86_MEM_READ))return 0;
  uint8_t ch=MEM8(ptr+i);
  if(ch==0){out[i]=0;return 1;}
  out[i]=(char)ch;
 }
 out[cap-1u]=0; return 0;
}
static int x86_fs_normalize(const char *src,char *dst,uint32_t cap){
 uint32_t di=0,seg_start=0;
 if(!src||!dst||cap<2u)return 0;
 dst[0]='/';
 di=1;
 for(uint32_t i=0;src[i];){
  while(src[i]=='/'||src[i]=='\\')i++;
  uint32_t start=i;
  while(src[i]&&src[i]!='/'&&src[i]!='\\')i++;
  uint32_t n=i-start;
  if(!n)continue;
  if(n==1u&&src[start]=='.')continue;
  if(n==2u&&src[start]=='.')return 0;
  if(di>1u){if(di+1u>=cap)return 0;dst[di++]='/';}
  if(di+n>=cap)return 0;
  for(uint32_t j=0;j<n;j++)dst[di++]=src[start+j];
  seg_start=di;
  (void)seg_start;
 }
 if(di==1u){if(cap<2u)return 0;dst[1]=0;}else dst[di]=0;
 return 1;
}
static int x86_fs_find_file(const char *path){
 for(uint32_t i=0;i<X86_FS_MAX_FILES;i++)if(x86_fs_files[i].used){
  uint32_t j=0;while(j<X86_FS_MAX_PATH&&x86_fs_files[i].path[j]&&path[j]&&x86_fs_files[i].path[j]==path[j])j++;
  if(j<X86_FS_MAX_PATH&&x86_fs_files[i].path[j]==0&&path[j]==0)return (int)i;
 }
 return -1;
}
static int x86_fs_find_free_file(void){for(uint32_t i=0;i<X86_FS_MAX_FILES;i++)if(!x86_fs_files[i].used)return (int)i;return -1;}
static int x86_fs_find_free_handle(void){for(uint32_t i=0;i<X86_FS_MAX_HANDLES;i++)if(!x86_fs_handles[i].used)return (int)i;return -1;}
static uint32_t x86_fs_handle_value(uint32_t index){return X86_FS_HANDLE_BASE+index;}
static int x86_fs_handle_index(uint32_t handle){if(handle<X86_FS_HANDLE_BASE||handle>=X86_FS_HANDLE_BASE+X86_FS_MAX_HANDLES)return -1;return (int)(handle-X86_FS_HANDLE_BASE);}
static int x86_fs_resize_file(uint32_t fi,uint32_t size){
 x86_fs_file_t *f=&x86_fs_files[fi];
 if(size<=f->capacity){f->size=size;return 1;}
 uint32_t cap=al4(size);
 if(cap<size)cap=size;
 uint32_t p=x86_mem_alloc_region(cap,X86_MEM_READ|X86_MEM_WRITE,6u);
 if(!p)return 0;
 for(uint32_t i=0;i<f->size;i++)wr8(p+i,MEM8(f->data+i));
 if(f->data){
  for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==f->data&&x86_mem_regions[i].kind==6u){x86_mem_regions[i].active=0;x86_mem_region_count--;break;}
 }
 f->data=p;f->capacity=cap;f->size=size;return 1;
}
static uint32_t x86_fs_mount_impl(const char *raw_path,uint32_t data,uint32_t size){
 char path[X86_FS_MAX_PATH];
 if(!x86_fs_normalize(raw_path,path,sizeof(path))){x86_fs_last_error=3;return 0;}
 if(size&&!x86_mem_region_find(data,size,X86_MEM_READ)){x86_fs_last_error=14;return 0;}
 int fi=x86_fs_find_file(path);
 if(fi<0)fi=x86_fs_find_free_file();
 if(fi<0){x86_fs_last_error=24;return 0;}
 x86_fs_file_t *f=&x86_fs_files[fi];
 if(!f->used){f->used=1;for(uint32_t i=0;i<X86_FS_MAX_PATH;i++){f->path[i]=path[i];if(!path[i])break;}}
 if(size==0){if(f->data){for(uint32_t i=0;i<X86_MEM_REGION_MAX;i++)if(x86_mem_regions[i].active&&x86_mem_regions[i].base==f->data&&x86_mem_regions[i].kind==6u){x86_mem_regions[i].active=0;x86_mem_region_count--;break;}}f->data=0;f->size=0;f->capacity=0;return 1;}
 if(!x86_fs_resize_file((uint32_t)fi,size)){x86_fs_last_error=12;return 0;}
 for(uint32_t i=0;i<size;i++)wr8(f->data+i,MEM8(data+i));
 return 1;
}
static uint32_t x86_fs_open_impl(const char *raw_path,uint32_t access,uint32_t flags){
 char path[X86_FS_MAX_PATH];
 if(!x86_fs_normalize(raw_path,path,sizeof(path))){x86_fs_last_error=3;return 0;}
 int fi=x86_fs_find_file(path);
 if(fi<0){
  if(!(flags&X86_FS_OPEN_CREATE)){x86_fs_last_error=2;return 0;}
  fi=x86_fs_find_free_file();
  if(fi<0){x86_fs_last_error=24;return 0;}
  x86_fs_files[fi].used=1;x86_fs_files[fi].data=0;x86_fs_files[fi].size=0;x86_fs_files[fi].capacity=0;
  for(uint32_t i=0;i<X86_FS_MAX_PATH;i++){x86_fs_files[fi].path[i]=path[i];if(!path[i])break;}
 }else if(flags&X86_FS_OPEN_TRUNCATE){x86_fs_resize_file((uint32_t)fi,0);}
 int hi=x86_fs_find_free_handle();
 if(hi<0){x86_fs_last_error=24;return 0;}
 x86_fs_handles[hi].used=1;x86_fs_handles[hi].file=(uint32_t)fi;x86_fs_handles[hi].pos=0;x86_fs_handles[hi].access=access;
 return x86_fs_handle_value((uint32_t)hi);
}
static uint32_t x86_fs_close_impl(uint32_t handle){
 int hi=x86_fs_handle_index(handle);
 if(hi<0||!x86_fs_handles[hi].used){x86_fs_last_error=6;return 0;}
 x86_fs_handles[hi].used=0;return 1;
}
static uint32_t x86_fs_read_impl(uint32_t handle,uint32_t dst,uint32_t size,uint32_t *read_out){
 if(read_out)*read_out=0;
 int hi=x86_fs_handle_index(handle);
 if(hi<0||!x86_fs_handles[hi].used){x86_fs_last_error=6;return 0;}
 x86_fs_handle_t *h=&x86_fs_handles[hi];x86_fs_file_t *f=&x86_fs_files[h->file];
 if(!(h->access&X86_FS_ACCESS_READ)){x86_fs_last_error=5;return 0;}
 if(size&&!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_fs_last_error=14;return 0;}
 uint32_t n=f->size>h->pos?f->size-h->pos:0;if(n>size)n=size;
 for(uint32_t i=0;i<n;i++)wr8(dst+i,MEM8(f->data+h->pos+i));
 h->pos+=n;if(read_out)*read_out=n;return 1;
}
static uint32_t x86_fs_write_impl(uint32_t handle,uint32_t src,uint32_t size,uint32_t *written_out){
 if(written_out)*written_out=0;
 int hi=x86_fs_handle_index(handle);
 if(hi<0||!x86_fs_handles[hi].used){x86_fs_last_error=6;return 0;}
 x86_fs_handle_t *h=&x86_fs_handles[hi];x86_fs_file_t *f=&x86_fs_files[h->file];
 if(!(h->access&X86_FS_ACCESS_WRITE)){x86_fs_last_error=5;return 0;}
 if(size&&!x86_mem_region_find(src,size,X86_MEM_READ)){x86_fs_last_error=14;return 0;}
 uint32_t end=h->pos+size;if(end<h->pos){x86_fs_last_error=8;return 0;}
 if(end>f->size&&!x86_fs_resize_file(h->file,end)){x86_fs_last_error=12;return 0;}
 for(uint32_t i=0;i<size;i++)wr8(f->data+h->pos+i,MEM8(src+i));
 h->pos=end;if(written_out)*written_out=size;return 1;
}
static uint32_t x86_fs_seek_impl(uint32_t handle,int32_t distance,uint32_t origin){
 int hi=x86_fs_handle_index(handle);
 if(hi<0||!x86_fs_handles[hi].used){x86_fs_last_error=6;return 0xFFFFFFFFu;}
 x86_fs_handle_t *h=&x86_fs_handles[hi];x86_fs_file_t *f=&x86_fs_files[h->file];
 int64_t base=origin==0?0:(origin==1?(int64_t)h->pos:(int64_t)f->size),next=base+(int64_t)distance;
 if(next<0||next>0xFFFFFFFFll){x86_fs_last_error=22;return 0xFFFFFFFFu;}
 h->pos=(uint32_t)next;return h->pos;
}
static uint32_t x86_fs_size_impl(uint32_t handle){
 int hi=x86_fs_handle_index(handle);
 if(hi<0||!x86_fs_handles[hi].used){x86_fs_last_error=6;return 0xFFFFFFFFu;}
 return x86_fs_files[x86_fs_handles[hi].file].size;
}
static uint32_t x86_fs_mount_impl_from_guest(uint32_t path_ptr,uint32_t data_ptr,uint32_t size){
 char raw[X86_FS_MAX_PATH];if(!x86_fs_guest_string(path_ptr,raw,sizeof(raw)))return 0;return x86_fs_mount_impl(raw,data_ptr,size);
}
static uint32_t x86_fs_open_impl_from_guest(uint32_t path_ptr,uint32_t access,uint32_t flags){
 char raw[X86_FS_MAX_PATH];if(!x86_fs_guest_string(path_ptr,raw,sizeof(raw)))return 0;return x86_fs_open_impl(raw,access,flags);
}
static uint32_t x86_fs_c5_read_count=0;
static uint32_t x86_fs_read_c5(uint32_t handle,uint32_t dst,uint32_t size){
 uint32_t n=0,ok=x86_fs_read_impl(handle,dst,size,&n);x86_fs_c5_read_count=n;return ok;
}
static uint32_t x86_fs_exists_impl(const char *raw_path){
 char path[X86_FS_MAX_PATH];if(!x86_fs_normalize(raw_path,path,sizeof(path)))return 0;
 return x86_fs_find_file(path)>=0?1u:0u;
}

/* C4 game registry: a deterministic, in-memory Win32-compatible subset.
 * It intentionally avoids the host OS registry. Keys and values are small and
 * fixed-capacity because this is a game compatibility facility, not OS emulation. */
#define X86_REG_MAX_KEYS 64u
#define X86_REG_MAX_VALUES 128u
#define X86_REG_MAX_PATH 256u
#define X86_REG_MAX_VALUE_NAME 128u
#define X86_REG_MAX_VALUE_DATA 4096u
#define X86_REG_HANDLE_BASE 0x2000u
#define X86_REG_HKEY_CURRENT_USER  0x80000001u
#define X86_REG_HKEY_LOCAL_MACHINE 0x80000002u
#define X86_REG_REG_SZ 1u
#define X86_REG_REG_EXPAND_SZ 2u
#define X86_REG_REG_BINARY 3u
#define X86_REG_REG_DWORD 4u
#define X86_REG_ERROR_SUCCESS 0u
#define X86_REG_ERROR_FILE_NOT_FOUND 2u
#define X86_REG_ERROR_ACCESS_DENIED 5u
#define X86_REG_ERROR_INVALID_HANDLE 6u
#define X86_REG_ERROR_INVALID_PARAMETER 87u
#define X86_REG_ERROR_MORE_DATA 234u
#define X86_REG_ERROR_ALREADY_EXISTS 183u
#define X86_REG_ERROR_OUTOFMEMORY 14u

typedef struct {
 uint32_t used;
 uint32_t hive;
 char path[X86_REG_MAX_PATH];
} x86_reg_key_t;
typedef struct {
 uint32_t used;
 uint32_t key;
 uint32_t type;
 uint32_t size;
 char name[X86_REG_MAX_VALUE_NAME];
 uint8_t data[X86_REG_MAX_VALUE_DATA];
} x86_reg_value_t;
static x86_reg_key_t x86_reg_keys[X86_REG_MAX_KEYS];
static x86_reg_value_t x86_reg_values[X86_REG_MAX_VALUES];
static uint32_t x86_reg_last_error=0;

static void x86_reg_set_error(uint32_t error){x86_reg_last_error=error;crt_last_error=error;}
static void x86_reg_reset(void){
 for(uint32_t i=0;i<X86_REG_MAX_KEYS;i++){x86_reg_keys[i].used=0;x86_reg_keys[i].hive=0;x86_reg_keys[i].path[0]=0;}
 for(uint32_t i=0;i<X86_REG_MAX_VALUES;i++){x86_reg_values[i].used=0;x86_reg_values[i].key=0;x86_reg_values[i].type=0;x86_reg_values[i].size=0;x86_reg_values[i].name[0]=0;}
 x86_reg_last_error=0;
}
static int x86_reg_hive(uint32_t handle){
 if(handle==X86_REG_HKEY_CURRENT_USER)return 1;
 if(handle==X86_REG_HKEY_LOCAL_MACHINE)return 2;
 if(handle>=X86_REG_HANDLE_BASE&&handle<X86_REG_HANDLE_BASE+X86_REG_MAX_KEYS){
  uint32_t i=handle-X86_REG_HANDLE_BASE;
  if(x86_reg_keys[i].used)return (int)x86_reg_keys[i].hive;
 }
 return 0;
}
static int x86_reg_key_index(uint32_t handle){
 if(handle<X86_REG_HANDLE_BASE||handle>=X86_REG_HANDLE_BASE+X86_REG_MAX_KEYS)return -1;
 uint32_t i=handle-X86_REG_HANDLE_BASE;
 return x86_reg_keys[i].used?(int)i:-1;
}
static int x86_reg_path_equal(const char *a,const char *b){
 uint32_t i=0;while(i<X86_REG_MAX_PATH&&a[i]&&b[i]){
  char ca=a[i],cb=b[i];
  if(ca>='a'&&ca<='z')ca=(char)(ca-'a'+'A');
  if(cb>='a'&&cb<='z')cb=(char)(cb-'a'+'A');
  if(ca!=cb)return 0;i++;
 }
 return i<X86_REG_MAX_PATH&&a[i]==0&&b[i]==0;
}
static int x86_reg_normalize_subkey(const char *src,char *dst,uint32_t cap){
 uint32_t di=0;
 if(!dst||cap<2u)return 0;
 for(uint32_t i=0;src&&src[i];){
  while(src[i]=='\\'||src[i]=='/')i++;
  uint32_t start=i;
  while(src[i]&&src[i]!='\\'&&src[i]!='/')i++;
  uint32_t n=i-start;
  if(!n)continue;
  if(n==1u&&src[start]=='.')continue;
  if(n==2u&&src[start]=='.')return 0;
  if(di&&di+1u>=cap)return 0;
  if(di)dst[di++]='\\';
  if(di+n>=cap)return 0;
  for(uint32_t j=0;j<n;j++)dst[di++]=src[start+j];
 }
 dst[di]=0;return 1;
}
static int x86_reg_find_key_path(uint32_t hive,const char *path){
 for(uint32_t i=0;i<X86_REG_MAX_KEYS;i++)if(x86_reg_keys[i].used&&x86_reg_keys[i].hive==hive&&x86_reg_path_equal(x86_reg_keys[i].path,path))return (int)i;
 return -1;
}
static int x86_reg_find_free_key(void){for(uint32_t i=0;i<X86_REG_MAX_KEYS;i++)if(!x86_reg_keys[i].used)return (int)i;return -1;}
static int x86_reg_find_value(uint32_t key,const char *name){
 for(uint32_t i=0;i<X86_REG_MAX_VALUES;i++)if(x86_reg_values[i].used&&x86_reg_values[i].key==key&&x86_reg_path_equal(x86_reg_values[i].name,name))return (int)i;
 return -1;
}
static int x86_reg_find_free_value(void){for(uint32_t i=0;i<X86_REG_MAX_VALUES;i++)if(!x86_reg_values[i].used)return (int)i;return -1;}
static uint32_t x86_reg_key_handle(uint32_t index){return X86_REG_HANDLE_BASE+index;}
static uint32_t x86_reg_build_path(uint32_t parent,const char *sub,char *out,uint32_t cap,uint32_t *hive_out){
 uint32_t hive=0;int pi=x86_reg_key_index(parent);
 if(parent==X86_REG_HKEY_CURRENT_USER)hive=1;else if(parent==X86_REG_HKEY_LOCAL_MACHINE)hive=2;else if(pi>=0)hive=x86_reg_keys[pi].hive;else return 0;
 char norm[X86_REG_MAX_PATH];
 if(!x86_reg_normalize_subkey(sub?sub:"",norm,sizeof(norm)))return 0;
 uint32_t di=0;
 if(pi>=0){while(di+1u<cap&&x86_reg_keys[pi].path[di]){out[di]=x86_reg_keys[pi].path[di];di++;}if(norm[0]){if(di+1u>=cap)return 0;out[di++]='\\';}}
 else if(norm[0]){ /* root handles have an empty relative path */ }
 for(uint32_t i=0;norm[i];i++){if(di+1u>=cap)return 0;out[di++]=norm[i];}
 out[di]=0;if(hive_out)*hive_out=hive;return 1;
}
static uint32_t x86_reg_open_impl(uint32_t parent,const char *sub,uint32_t *out_handle){
 if(out_handle)*out_handle=0;
 char path[X86_REG_MAX_PATH];uint32_t hive=0;
 if(!x86_reg_build_path(parent,sub,path,sizeof(path),&hive)){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(!path[0]){if(out_handle)*out_handle=parent; x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;}
 int ki=x86_reg_find_key_path(hive,path);
 if(ki<0){x86_reg_set_error(X86_REG_ERROR_FILE_NOT_FOUND);return X86_REG_ERROR_FILE_NOT_FOUND;}
 if(out_handle)*out_handle=x86_reg_key_handle((uint32_t)ki);x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_create_impl(uint32_t parent,const char *sub,uint32_t *out_handle,uint32_t *disposition){
 if(out_handle)*out_handle=0;if(disposition)*disposition=1u;
 char norm[X86_REG_MAX_PATH],full[X86_REG_MAX_PATH];uint32_t hive=0;int pi=x86_reg_key_index(parent);
 if(parent!=X86_REG_HKEY_CURRENT_USER&&parent!=X86_REG_HKEY_LOCAL_MACHINE&&pi<0){x86_reg_set_error(X86_REG_ERROR_INVALID_HANDLE);return X86_REG_ERROR_INVALID_HANDLE;}
 if(!x86_reg_normalize_subkey(sub?sub:"",norm,sizeof(norm))){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(!x86_reg_build_path(parent,norm,full,sizeof(full),&hive)){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(!full[0]){if(out_handle)*out_handle=parent;if(disposition)*disposition=2u;x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;}
 uint32_t final_existed=x86_reg_find_key_path(hive,full)>=0?1u:0u;
 /* RegCreateKeyExA creates missing intermediate keys as part of the requested path. */
 uint32_t start=0,last=0;
 while(1){
  while(full[start]=='\\')start++;
  uint32_t i=start;while(full[i]&&full[i]!='\\')i++;
  if(i>start){
   char prefix[X86_REG_MAX_PATH];uint32_t n=i;
   if(n>=sizeof(prefix)){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
   for(uint32_t j=0;j<n;j++)prefix[j]=full[j];prefix[n]=0;
   int existing=x86_reg_find_key_path(hive,prefix);
   if(existing<0){
    int created=x86_reg_find_free_key();
    if(created<0){x86_reg_set_error(X86_REG_ERROR_OUTOFMEMORY);return X86_REG_ERROR_OUTOFMEMORY;}
    x86_reg_keys[created].used=1;x86_reg_keys[created].hive=hive;
    for(uint32_t j=0;j<=n;j++)x86_reg_keys[created].path[j]=prefix[j];
    last=(uint32_t)created;
   }else last=(uint32_t)existing;
  }
  if(!full[i])break;
  start=i+1u;
 }
 if(out_handle)*out_handle=x86_reg_key_handle(last);
 if(disposition)*disposition=final_existed?2u:1u;
 x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_close_impl(uint32_t handle){
 if(handle==X86_REG_HKEY_CURRENT_USER||handle==X86_REG_HKEY_LOCAL_MACHINE){x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;}
 int ki=x86_reg_key_index(handle);if(ki<0){x86_reg_set_error(X86_REG_ERROR_INVALID_HANDLE);return X86_REG_ERROR_INVALID_HANDLE;}
 x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_set_value_impl(uint32_t handle,const char *name,uint32_t type,const uint8_t *data,uint32_t size){
 int ki=x86_reg_key_index(handle);if(ki<0){x86_reg_set_error(X86_REG_ERROR_INVALID_HANDLE);return X86_REG_ERROR_INVALID_HANDLE;}
 if(type!=X86_REG_REG_SZ&&type!=X86_REG_REG_EXPAND_SZ&&type!=X86_REG_REG_BINARY&&type!=X86_REG_REG_DWORD){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(size>X86_REG_MAX_VALUE_DATA||(type==X86_REG_REG_DWORD&&size!=4u)){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(size&&!data){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 int vi=x86_reg_find_value((uint32_t)ki,name?name:"");
 if(vi<0){vi=x86_reg_find_free_value();if(vi<0){x86_reg_set_error(X86_REG_ERROR_OUTOFMEMORY);return X86_REG_ERROR_OUTOFMEMORY;}x86_reg_values[vi].used=1;x86_reg_values[vi].key=(uint32_t)ki;}
 x86_reg_value_t *v=&x86_reg_values[vi];v->type=type;v->size=size;
 for(uint32_t i=0;i<X86_REG_MAX_VALUE_NAME;i++){v->name[i]=(name&&name[i])?name[i]:0;if(!name||!name[i])break;}
 for(uint32_t i=0;i<size;i++)v->data[i]=data[i];
 x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_query_value_impl(uint32_t handle,const char *name,uint32_t *type,uint8_t *data,uint32_t *size){
 int ki=x86_reg_key_index(handle);if(ki<0){x86_reg_set_error(X86_REG_ERROR_INVALID_HANDLE);return X86_REG_ERROR_INVALID_HANDLE;}
 int vi=x86_reg_find_value((uint32_t)ki,name?name:"");if(vi<0){x86_reg_set_error(X86_REG_ERROR_FILE_NOT_FOUND);return X86_REG_ERROR_FILE_NOT_FOUND;}
 x86_reg_value_t *v=&x86_reg_values[vi];
 if(type)*type=v->type;
 if(!size){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 uint32_t capacity=*size;*size=v->size;
 if(v->size&&!data){x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;}
 if(capacity<v->size){x86_reg_set_error(X86_REG_ERROR_MORE_DATA);return X86_REG_ERROR_MORE_DATA;}
 if(v->size&&data&&!x86_mem_region_find((uint32_t)(uintptr_t)data,v->size,X86_MEM_WRITE)){x86_reg_set_error(X86_REG_ERROR_INVALID_PARAMETER);return X86_REG_ERROR_INVALID_PARAMETER;}
 if(v->size&&data)for(uint32_t i=0;i<v->size;i++)data[i]=v->data[i];
 x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_create_guest_impl(uint32_t parent,uint32_t sub_ptr,uint32_t out_ptr,uint32_t *handle,uint32_t *disp){
 char raw[X86_REG_MAX_PATH];if(sub_ptr&&!x86_fs_guest_string(sub_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;
 uint32_t result=x86_reg_create_impl(parent,sub_ptr?raw:"",handle,disp);
 if(result==X86_REG_ERROR_SUCCESS&&(!out_ptr||!x86_mem_region_find(out_ptr,4u,X86_MEM_WRITE)))return X86_REG_ERROR_INVALID_PARAMETER;
 if(result==X86_REG_ERROR_SUCCESS)wr32(out_ptr,*handle);
 return result;
}
static uint32_t x86_reg_set_guest_impl(uint32_t handle,uint32_t name_ptr,uint32_t type,uint32_t data_ptr,uint32_t size){
 char raw[X86_REG_MAX_VALUE_NAME];if(name_ptr&&!x86_fs_guest_string(name_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;
 if(size&&!x86_mem_region_find(data_ptr,size,X86_MEM_READ))return X86_REG_ERROR_INVALID_PARAMETER;
 uint8_t tmp[X86_REG_MAX_VALUE_DATA];if(size>sizeof(tmp))return X86_REG_ERROR_INVALID_PARAMETER;
 for(uint32_t i=0;i<size;i++)tmp[i]=MEM8(data_ptr+i);
 return x86_reg_set_value_impl(handle,name_ptr?raw:"",type,tmp,size);
}
static uint32_t x86_reg_delete_value_impl(uint32_t handle,const char *name){
 int ki=x86_reg_key_index(handle);if(ki<0){x86_reg_set_error(X86_REG_ERROR_INVALID_HANDLE);return X86_REG_ERROR_INVALID_HANDLE;}
 int vi=x86_reg_find_value((uint32_t)ki,name?name:"");if(vi<0){x86_reg_set_error(X86_REG_ERROR_FILE_NOT_FOUND);return X86_REG_ERROR_FILE_NOT_FOUND;}
 x86_reg_values[vi].used=0;x86_reg_set_error(X86_REG_ERROR_SUCCESS);return X86_REG_ERROR_SUCCESS;
}
static uint32_t x86_reg_key_exists_impl(uint32_t parent,const char *sub){
 char path[X86_REG_MAX_PATH];uint32_t hive=0;
 if(!x86_reg_build_path(parent,sub,path,sizeof(path),&hive))return 0;
 return x86_reg_find_key_path(hive,path)>=0?1u:0u;
}
static uint32_t x86_reg_value_exists_impl(uint32_t handle,const char *name){
 int ki=x86_reg_key_index(handle);if(ki<0)return 0;
 return x86_reg_find_value((uint32_t)ki,name?name:"")>=0?1u:0u;
}

static uint32_t guest_heap=GUEST_HEAP_BASE;
static uint32_t import_resolved=0,import_failed=0;
static uint32_t last_unresolved_gdr=0xFFFFFFFFu;

/* Guest Dependency Resolution (GDR) provenance.
 * Each named PE import gets one stable record so the browser shell can distinguish:
 *   - what the game statically requires (DLL + symbol + IAT slot),
 *   - whether the current runtime resolved it to a builtin host target, and
 *   - whether that exact IAT slot was actually called during this run.
 * This deliberately keeps the provenance keyed by IAT address rather than by
 * "last resolved import", which is only a scan-time diagnostic. */
#define X86_GDR_MAX_IMPORTS 4096u
enum {
 X86_GDR_UNRESOLVED=0u,
 X86_GDR_RESOLVED=1u
};
typedef struct {
 uint32_t dll_rva;
 uint32_t func_rva;
 uint32_t iat_rva;
 uint32_t target;
 uint32_t status;
 uint32_t call_count;
} x86_gdr_record_t;
static x86_gdr_record_t x86_gdr[X86_GDR_MAX_IMPORTS];
static uint32_t x86_gdr_count=0;
static uint32_t message_count=0,message_last=0,message_quit=0,mouse_clicks=0,mouse_right_clicks=0,mouse_middle_clicks=0,mouse_moves=0;
static uint32_t surface_width=640,surface_height=360;
static uint32_t gl_context=1,gl_current_context=0,gl_mode=0;
static int32_t gl_viewport_x=0,gl_viewport_y=0,gl_viewport_w=640,gl_viewport_h=360;
static float gl_clear_r=0.0f,gl_clear_g=0.0f,gl_clear_b=0.0f,gl_clear_a=1.0f;
static float gl_color_r=1.0f,gl_color_g=1.0f,gl_color_b=1.0f,gl_color_a=1.0f;
static float gl_vertices[64][3];
static uint32_t gl_vertex_count=0;
static uint32_t gl_begin_mode=0;
static uint32_t last_import_dll=0,last_import_func=0,last_import_thunk=0,last_import_target=0;
static uint32_t last_failed_import_dll=0,last_failed_import_func=0;

static uint32_t al4(uint32_t x){return(x+3u)&~3u;}
static int streq_ascii(uint32_t p,const char*s){
 uint32_t i=0; while(s[i]){if(MEM8(p+i)!=(uint8_t)s[i])return 0;i++;}
 return MEM8(p+i)==0;
}
static uint32_t guest_alloc_raw(uint32_t n){
 if(!n)return 0;
 uint32_t a=al4(guest_heap);
 uint32_t end=a+al4(n);
 if(end<a||end>GUEST_HEAP_LIMIT||!x86_mem_ensure_wasm(end))return 0; /* x86_alloc'd staging buffers must be backed by real wasm pages */
 guest_heap=end; return a;
}
/* ---- Win32 / CRT shim layer (table driven) -------------------------------
 * Name-matched against any DLL (kernel32, api-ms-win-crt-*, VCRUNTIME140...).
 * Each entry: id, number of 32-bit stack args, callee_pops (1=stdcall, 0=cdecl).
 * Shim runs with [ESP]=return address; stdcall shims pop their own args here
 * (call site then discards the return slot, same as VirtualAlloc above). */
#define API_SHIM_BASE (API_BASE+0x00020000u)
#define SHIM_LIST(X) \
 X(GetSystemTimeAsFileTime,1,1) X(GetCurrentProcessId,0,1) X(GetCurrentThreadId,0,1) X(GetCurrentProcess,0,1) \
 X(QueryPerformanceCounter,1,1) X(QueryPerformanceFrequency,1,1) X(IsProcessorFeaturePresent,1,1) \
 X(InitializeSListHead,1,1) X(SetUnhandledExceptionFilter,1,1) X(UnhandledExceptionFilter,1,1) X(IsDebuggerPresent,0,1) \
 X(TerminateProcess,2,1) X(GetModuleHandleA,1,1) X(GetModuleHandleW,1,1) \
 X(InitializeCriticalSection,1,1) X(InitializeCriticalSectionAndSpinCount,2,1) X(EnterCriticalSection,1,1) \
 X(LeaveCriticalSection,1,1) X(DeleteCriticalSection,1,1) X(TryEnterCriticalSection,1,1) \
 X(TlsAlloc,0,1) X(TlsFree,1,1) X(TlsGetValue,1,1) X(TlsSetValue,2,1) \
 X(FlsAlloc,1,1) X(FlsFree,1,1) X(FlsSetValue,2,1) \
 X(Sleep,1,1) X(GetStdHandle,1,1) X(GetSystemInfo,1,1) X(GetLocalTime,1,1) X(GetEnvironmentVariableA,3,1) \
 X(GetCurrentDirectoryA,2,1) X(GlobalAlloc,2,1) X(GlobalLock,1,1) X(GlobalUnlock,1,1) \
 X(SetThreadExecutionState,1,1) X(SetThreadPriority,2,1) X(VirtualQuery,3,1) X(WriteConsoleA,5,1) \
 X(CreateEventW,4,1) X(SetEvent,1,1) X(ResetEvent,1,1) X(WaitForSingleObject,2,1) X(WaitForSingleObjectEx,3,1) \
 X(GetProcAddress,2,1) X(LoadLibraryA,1,1) X(LoadLibraryW,1,1) X(FreeLibrary,1,1) X(GetFileAttributesA,1,1) \
 X(timeGetTime,0,1) X(timeBeginPeriod,1,1) X(timeEndPeriod,1,1) \
 X(_set_app_type,1,0) X(_configure_narrow_argv,1,0) X(_initialize_narrow_environment,0,0) \
 X(_get_initial_narrow_environment,0,0) X(__p___argc,0,0) X(__p___argv,0,0) X(__p__commode,0,0) \
 X(_set_fmode,1,0) X(_controlfp_s,3,0) X(_configthreadlocale,1,0) X(_set_new_mode,1,0) X(__setusermatherr,1,0) \
 X(_initialize_onexit_table,1,0) X(_register_onexit_function,2,0) X(_crt_atexit,1,0) \
 X(_register_thread_local_exe_atexit_callback,1,0) X(_seh_filter_exe,4,0) \
 X(_exit,1,0) X(exit,1,0) X(_cexit,0,0) X(_c_exit,0,0) X(abort,0,0) X(terminate,0,0) \
 X(malloc,1,0) X(free,1,0) X(calloc,2,0) X(memset,3,0) X(memcpy,3,0) X(memmove,3,0) X(strlen,1,0) X(_errno,0,0)
enum {
#define X(n,a,c) SHIM_##n,
 SHIM_LIST(X)
#undef X
 SHIM_COUNT
};
static const struct{const char*name;uint8_t argc,callee_pops;}shim_tab[]={
#define X(n,a,c) {#n,a,c},
 SHIM_LIST(X)
#undef X
};
static uint32_t shim_tls[64],shim_fls[64],shim_tls_next=0,shim_fls_next=0,shim_handle=0x100u;
static uint32_t shim_qpc=0,shim_ft_lo=0xD53E8000u,shim_ft_hi=0x01DC0000u;
static uint32_t shim_initterm=0,shim_initterm_e=0,shim_argc_p=0,shim_argv_p=0,shim_env_p=0,shim_commode_p=0,shim_errno_p=0,shim_onexit_dummy=0;
static int x87_push(double v);
/* ---- XAPI registry: functions described by .xapi manifests ----------------
 * The shell parses the merged game .xapi and registers each function here
 * (x86_xapi_register). resolve_builtin() binds matching PE imports to
 * API_XAPI_BASE+index*4; xapi_call() marshals stack args per the declared
 * signature into xapi_slots[] (all as doubles) and calls the host bridge.
 * Type codes: 0 void, 1 u32, 2 i32, 3 ptr, 4 f32, 5 f64. ABI: 0 stdcall, 1 cdecl. */
#define API_XAPI_BASE (API_BASE+0x00030000u)
#define XAPI_MAX_FUNCS 2048u
#define XAPI_MAX_ALIASES 128u
#define XAPI_POOL_SIZE 98304u
#define XAPI_SLOT_RET 15u
extern int32_t z_host_xapi_call(int32_t id,int32_t argc);
typedef struct{uint32_t id,lib_off,name_off,calls;uint8_t abi,nargs,ret,args[16];}x86_xapi_fn_t;
static x86_xapi_fn_t xapi_fn[XAPI_MAX_FUNCS];
static uint32_t xapi_count=0,xapi_pool_used=0,xapi_alias_count=0,xapi_duplicate_count=0,
 xapi_alias_from[XAPI_MAX_ALIASES],xapi_alias_to[XAPI_MAX_ALIASES];
static uint32_t xapi_last_id=0,xapi_last_idx=0xFFFFFFFFu;
static char xapi_pool[XAPI_POOL_SIZE];
static uint8_t xapi_scratch[512];
static double xapi_slots[16];
static uint32_t xapi_pool_add(const uint8_t*s,uint32_t n){
 if(xapi_pool_used+n+1u>XAPI_POOL_SIZE)return 0xFFFFFFFFu;
 uint32_t o=xapi_pool_used;for(uint32_t i=0;i<n;i++)xapi_pool[o+i]=(char)s[i];xapi_pool[o+n]=0;xapi_pool_used+=n+1u;return o;
}
static uint32_t xapi_len(const uint8_t*s,uint32_t max){uint32_t n=0;while(n<max&&s[n])n++;return n;}
static char xapi_lc(char c){return (c>='A'&&c<='Z')?(char)(c+32):c;}
static int xapi_streqi_guest(uint32_t p,const char*s){
 uint32_t i=0;for(;s[i];i++)if(xapi_lc((char)MEM8(p+i))!=xapi_lc(s[i]))return 0;
 return MEM8(p+i)==0;
}
static int xapi_streq_guest(uint32_t p,const char*s){return streq_ascii(p,s);}
static int xapi_cstreq(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int32_t xapi_lookup(uint32_t dll,uint32_t name){
 for(uint32_t i=0;i<xapi_count;i++){
  const char*lib=xapi_pool+xapi_fn[i].lib_off,*fn=xapi_pool+xapi_fn[i].name_off;
  if(!xapi_streq_guest(name,fn))continue;
  if(xapi_streqi_guest(dll,lib))return (int32_t)i;
  for(uint32_t a=0;a<xapi_alias_count;a++)
   if(xapi_streqi_guest(dll,xapi_pool+xapi_alias_from[a])&&xapi_cstreq(xapi_pool+xapi_alias_to[a],lib))return (int32_t)i;
 }
 return -1;
}
static uint32_t xapi_call(uint32_t idx){
 x86_xapi_fn_t*f=&xapi_fn[idx];
 uint32_t sp=regs[R_ESP]+4u,off=0;
 for(uint32_t k=0;k<f->nargs&&k<16u;k++){
  uint8_t t=f->args[k];
  if(t==5){union{uint64_t u;double d;}c;c.u=(uint64_t)rd32(sp+off)|((uint64_t)rd32(sp+off+4u)<<32);xapi_slots[k]=c.d;off+=8u;}
  else if(t==4){union{uint32_t u;float f;}c;c.u=rd32(sp+off);xapi_slots[k]=(double)c.f;off+=4u;}
  else if(t==2){xapi_slots[k]=(double)(int32_t)rd32(sp+off);off+=4u;}
  else{xapi_slots[k]=(double)rd32(sp+off);off+=4u;}
 }
 xapi_slots[XAPI_SLOT_RET]=0.0;
 xapi_last_id=f->id;xapi_last_idx=idx;f->calls++;
 int32_t r=z_host_xapi_call((int32_t)f->id,(int32_t)f->nargs);
 if(f->ret==4||f->ret==5){if(!x87_push(xapi_slots[XAPI_SLOT_RET]))return 0;}
 else regs[R_EAX]=(uint32_t)r;
 if(f->abi==0)regs[R_ESP]+=off;
 return 1;
}
static uint32_t shim_emit(const uint8_t*b,uint32_t n){uint32_t a=guest_alloc_raw(n);if(!a)return 0;for(uint32_t i=0;i<n;i++)MEM8(a+i)=b[i];return a;}
static uint32_t shim_resolve(uint32_t name){
 /* _initterm/_initterm_e call guest function pointers, so they are real guest code rather than host shims. */
 if(streq_ascii(name,"_initterm")){
  static const uint8_t c[]={0x56,0x8B,0x74,0x24,0x08,0x3B,0x74,0x24,0x0C,0x73,0x0D,0x8B,0x06,0x85,0xC0,0x74,0x02,0xFF,0xD0,0x83,0xC6,0x04,0xEB,0xED,0x5E,0xC3};
  if(!shim_initterm)shim_initterm=shim_emit(c,sizeof c);
  return shim_initterm;
 }
 if(streq_ascii(name,"_initterm_e")){
  static const uint8_t c[]={0x56,0x8B,0x74,0x24,0x08,0x3B,0x74,0x24,0x0C,0x73,0x11,0x8B,0x06,0x85,0xC0,0x74,0x06,0xFF,0xD0,0x85,0xC0,0x75,0x07,0x83,0xC6,0x04,0xEB,0xE9,0x33,0xC0,0x5E,0xC3};
  if(!shim_initterm_e)shim_initterm_e=shim_emit(c,sizeof c);
  return shim_initterm_e;
 }
 for(uint32_t i=0;i<SHIM_COUNT;i++)if(streq_ascii(name,shim_tab[i].name))return API_SHIM_BASE+i*4u;
 return 0;
}
static uint16_t rd16(uint32_t p);
static uint32_t x86_dll_get_proc(uint32_t module,uint32_t name);
static uint32_t x86_dll_module_for_name(uint32_t name);
static uint32_t x86_dll_module_for_wide_name(uint32_t p);
static uint32_t x86_dll_load_registered(uint32_t name);
static void x86_dll_rebind_all(void);
static uint32_t x86_crt_strlen(uint32_t s);

static uint32_t shim_call(uint32_t idx){
 uint32_t sp=regs[R_ESP];
 #define ARG(n) rd32(sp+4u+4u*(n))
 uint32_t r=0;
 crt_last_shim_index=idx;
 crt_last_shim_target=API_SHIM_BASE+idx*4u;
 crt_last_shim_argc=shim_tab[idx].argc;
 crt_last_shim_arg0=shim_tab[idx].argc?ARG(0):0u;
 switch(idx){
  case SHIM_GetSystemTimeAsFileTime:{shim_ft_lo+=100000u;if(shim_ft_lo<100000u)shim_ft_hi++;uint32_t p=ARG(0);wr32(p,shim_ft_lo);wr32(p+4u,shim_ft_hi);break;}
  case SHIM_GetCurrentProcessId:r=0x1234u;break;
  case SHIM_GetCurrentThreadId:r=1u;break;
  case SHIM_GetCurrentProcess:r=0xFFFFFFFFu;break;
  case SHIM_QueryPerformanceCounter:{shim_qpc+=10000u;uint32_t p=ARG(0);wr32(p,shim_qpc);wr32(p+4u,0);r=1;break;}
  case SHIM_QueryPerformanceFrequency:{uint32_t p=ARG(0);wr32(p,10000000u);wr32(p+4u,0);r=1;break;}
  case SHIM_IsProcessorFeaturePresent:{uint32_t f=ARG(0);r=(f==6u||f==10u||f==13u)?1u:0u;break;} /* SSE, SSE2, SSE3: advertise what the CPU implements */
  case SHIM_InitializeSListHead:{uint32_t p=ARG(0);wr32(p,0);wr32(p+4u,0);break;}
  case SHIM_UnhandledExceptionFilter:{
   /* Guest is reporting a fatal condition. Freeze here so the trace/stack still show what led to it. */
   if(!crash_hit){
    crash_hit=1u;crash_return_eip=rd32(sp);crash_arg0=ARG(0);
    for(uint32_t i=0;i<32u;i++)crash_stack[i]=rd32(sp+4u*i);
    uint32_t bp=regs[R_EBP],last=sp;crash_nframes=0u;
    while(crash_nframes<16u&&bp>last&&bp-sp<0x100000u){crash_frames[crash_nframes++]=rd32(bp+4u);last=bp;bp=rd32(bp);}
    crt_last_termination_kind=8u;crt_last_termination_caller=crt_last_shim_caller;
    crt_last_termination_return_eip=crash_return_eip;crt_last_termination_target=crt_last_shim_target;crt_last_termination_arg0=0xC0000409u;
    crt_exit_code=0xC0000409u;crt_exited=1u;halted=1;
   }
   r=0;break;}
  case SHIM_TerminateProcess:
   crt_last_termination_kind=7u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=ARG(1);
   crt_exit_code=crt_last_termination_arg0;
   crt_exited=1u; halted=1; r=1; break;
  case SHIM_GetModuleHandleA:r=ARG(0)?x86_dll_module_for_name(ARG(0)):image_base;break;
  case SHIM_GetModuleHandleW:r=ARG(0)?x86_dll_module_for_wide_name(ARG(0)):image_base;break;
  case SHIM_InitializeCriticalSectionAndSpinCount:case SHIM_TryEnterCriticalSection:r=1;break;
  case SHIM_TlsAlloc:r=(shim_tls_next<64u)?shim_tls_next++:0xFFFFFFFFu;break;
  case SHIM_TlsFree:case SHIM_FlsFree:r=1;break;
  case SHIM_TlsGetValue:{uint32_t i=ARG(0);r=i<64u?shim_tls[i]:0u;break;}
  case SHIM_TlsSetValue:{uint32_t i=ARG(0);if(i<64u){shim_tls[i]=ARG(1);r=1;}break;}
  case SHIM_FlsAlloc:r=(shim_fls_next<64u)?shim_fls_next++:0xFFFFFFFFu;break;
  case SHIM_FlsSetValue:{uint32_t i=ARG(0);if(i<64u){shim_fls[i]=ARG(1);r=1;}break;}
  case SHIM_GetStdHandle:r=0x100u+(ARG(0)&0xFu);break;
  case SHIM_GetSystemInfo:{uint32_t p=ARG(0);for(uint32_t i=0;i<36u;i+=4u)wr32(p+i,0);wr32(p+4u,4096u);wr32(p+8u,0x10000u);wr32(p+12u,0x7FFEFFFFu);wr32(p+16u,1u);wr32(p+20u,1u);wr32(p+24u,586u);wr32(p+28u,0x10000u);break;}
  case SHIM_GetLocalTime:{uint32_t p=ARG(0);for(uint32_t i=0;i<16u;i+=4u)wr32(p+i,0);wr16(p,2026u);wr16(p+2u,10u);wr16(p+6u,4u);break;}
  case SHIM_GetEnvironmentVariableA:r=0;break;
  case SHIM_GetCurrentDirectoryA:{uint32_t b=ARG(1);if(b){wr8(b,'C');wr8(b+1u,':');wr8(b+2u,'\\');wr8(b+3u,0);}r=3u;break;}
  case SHIM_GlobalAlloc:r=guest_alloc_raw(ARG(1));break;
  case SHIM_GlobalLock:r=ARG(0);break;
  case SHIM_GlobalUnlock:r=1;break;
  case SHIM_WriteConsoleA:r=1;break;
  case SHIM_CreateEventW:r=shim_handle++;break;
  case SHIM_GetProcAddress:r=x86_dll_get_proc(ARG(0),ARG(1));break;
  case SHIM_LoadLibraryA:r=x86_dll_load_registered(ARG(0));break;
  case SHIM_LoadLibraryW:{uint32_t p=ARG(0),q=guest_alloc_raw(96),i=0;for(;i<95u&&MEM8(p+i*2u);i++){uint16_t w=rd16(p+i*2u);wr8(q+i,(uint8_t)(w<128u?w:'?'));}wr8(q+i,0);r=x86_dll_load_registered(q);break;}
  case SHIM_FreeLibrary:r=1;break;
  case SHIM_SetEvent:case SHIM_ResetEvent:case SHIM_SetThreadPriority:case SHIM_timeBeginPeriod:case SHIM_timeEndPeriod:r=1;break;
  case SHIM_timeGetTime:shim_qpc+=16u;r=shim_qpc/10000u*16u+1234u;break;
  case SHIM_GetFileAttributesA:r=0xFFFFFFFFu;break;
  case SHIM___p___argc:if(!shim_argc_p){shim_argc_p=guest_alloc_raw(4);wr32(shim_argc_p,0);}r=shim_argc_p;break;
  case SHIM___p___argv:if(!shim_argv_p){shim_argv_p=guest_alloc_raw(8);wr32(shim_argv_p,0);}r=shim_argv_p;break;
  case SHIM__get_initial_narrow_environment:if(!shim_env_p){shim_env_p=guest_alloc_raw(8);wr32(shim_env_p,0);}r=shim_env_p;break;
  case SHIM___p__commode:if(!shim_commode_p){shim_commode_p=guest_alloc_raw(4);wr32(shim_commode_p,0);}r=shim_commode_p;break;
  case SHIM__errno:if(!shim_errno_p){shim_errno_p=guest_alloc_raw(4);wr32(shim_errno_p,0);}r=shim_errno_p;break;
  case SHIM__exit:
   crt_last_termination_kind=2u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=ARG(0);
   if(!crt_started)x86_crt_startup();
   crt_exit_code=crt_last_termination_arg0;
   crt_exited=1u;
   halted=1;
   break;
  case SHIM_exit:
   crt_last_termination_kind=1u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=ARG(0);
   x86_crt_exit(crt_last_termination_arg0);
   halted=1;
   break;
  case SHIM__cexit:
   crt_last_termination_kind=5u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=0u;
   x86_crt_exit(0u);
   halted=1;
   break;
  case SHIM__c_exit:
   crt_last_termination_kind=6u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=0u;
   if(!crt_started)x86_crt_startup();
   crt_exit_code=0u; crt_exited=1u;
   halted=1;
   break;
  case SHIM_abort:
   crt_last_termination_kind=3u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=3u;
   if(!crt_started)x86_crt_startup();
   crt_exit_code=3u; crt_exited=1u;
   halted=1;
   break;
  case SHIM_terminate:
   crt_last_termination_kind=4u;
   crt_last_termination_caller=crt_last_shim_caller;
   crt_last_termination_return_eip=rd32(sp);
   crt_last_termination_target=crt_last_shim_target;
   crt_last_termination_arg0=3u;
   if(!crt_started)x86_crt_startup();
   crt_exit_code=3u; crt_exited=1u;
   halted=1;
   break;
  case SHIM_malloc:r=x86_crt_malloc_impl(ARG(0));break;
  case SHIM_free:break;
  case SHIM_calloc:{uint32_t n=ARG(0)*ARG(1);r=x86_crt_malloc_impl(n);if(r)for(uint32_t i=0;i<n;i++)wr8(r+i,0);break;}
  case SHIM_memset:{uint32_t d=ARG(0),n=ARG(2);uint8_t v=(uint8_t)ARG(1);for(uint32_t i=0;i<n;i++)wr8(d+i,v);r=d;break;}
  case SHIM_memcpy:case SHIM_memmove:{uint32_t d=ARG(0),s=ARG(1),n=ARG(2);if(d<=s||d>=s+n){for(uint32_t i=0;i<n;i++)wr8(d+i,MEM8(s+i));}else{for(uint32_t i=n;i>0;i--)wr8(d+i-1u,MEM8(s+i-1u));}r=d;break;}
  case SHIM_strlen:{uint32_t p=ARG(0),n=0;while(MEM8(p+n))n++;r=n;break;}
  default:break; /* everything else: success/0, args popped per table */
 }
 #undef ARG
 regs[R_EAX]=r;
 if(shim_tab[idx].callee_pops)regs[R_ESP]+=shim_tab[idx].argc*4u;
 return 1;
}
static uint32_t resolve_builtin(uint32_t dll,uint32_t name){
 {uint32_t sh=shim_resolve(name);if(sh&&!streq_ascii(dll,"XWASMHOST.dll")){ if(!(streq_ascii(name,"GetTickCount")))return sh;}}
 /* First compatibility seed: enough structure to grow into real Win32 DLLs. */
 if(streq_ascii(dll,"KERNEL32.dll")||streq_ascii(dll,"kernel32.dll")){
  if(streq_ascii(name,"GetTickCount"))return API_GETTICKCOUNT;
 }
 if(streq_ascii(dll,"XWASMHOST.dll")||streq_ascii(dll,"xwasmhost.dll")){
  if(streq_ascii(name,"z_host_log"))return API_XWASM_LOG;
 }
 if(streq_ascii(dll,"KERNEL32.dll")||streq_ascii(dll,"kernel32.dll")){
  if(streq_ascii(name,"VirtualAlloc"))return API_VIRTUALALLOC;
  if(streq_ascii(name,"VirtualFree"))return API_VIRTUALFREE;
 }
 if(streq_ascii(dll,"USER32.dll")||streq_ascii(dll,"user32.dll")){
  if(streq_ascii(name,"CreateWindowExA"))return API_USER32_CREATEWINDOWEXA;
  if(streq_ascii(name,"ShowWindow"))return API_USER32_SHOWWINDOW;
  if(streq_ascii(name,"GetDC"))return API_USER32_GETDC;
  if(streq_ascii(name,"ReleaseDC"))return API_USER32_RELEASEDC;
 }
 if(streq_ascii(dll,"GDI32.dll")||streq_ascii(dll,"gdi32.dll")){
  if(streq_ascii(name,"SetPixel"))return API_GDI32_SETPIXEL;
  if(streq_ascii(name,"Rectangle"))return API_GDI32_RECTANGLE;
  if(streq_ascii(name,"SwapBuffers"))return API_GDI32_SWAPBUFFERS;
  if(streq_ascii(name,"ChoosePixelFormat"))return API_GDI32_CHOOSEPIXELFORMAT;
  if(streq_ascii(name,"SetPixelFormat"))return API_GDI32_SETPIXELFORMAT;
 }
 if(streq_ascii(dll,"OPENGL32.dll")||streq_ascii(dll,"opengl32.dll")){
  if(streq_ascii(name,"wglCreateContext"))return API_OPENGL32_WGLCREATECONTEXT;
  if(streq_ascii(name,"wglDeleteContext"))return API_OPENGL32_WGLDELETECONTEXT;
  if(streq_ascii(name,"wglMakeCurrent"))return API_OPENGL32_WGLMAKECURRENT;
  if(streq_ascii(name,"wglGetCurrentContext"))return API_OPENGL32_WGLGETCURRENTCONTEXT;
  if(streq_ascii(name,"wglShareLists"))return API_OPENGL32_WGLSHARELISTS;
  if(streq_ascii(name,"wglGetProcAddress"))return API_OPENGL32_WGLGETPROCADDRESS;
  if(streq_ascii(name,"glClearColor"))return API_OPENGL32_GLCLEARCOLOR;
  if(streq_ascii(name,"glClear"))return API_OPENGL32_GLCLEAR;
  if(streq_ascii(name,"glViewport"))return API_OPENGL32_GLVIEWPORT;
  if(streq_ascii(name,"glBegin"))return API_OPENGL32_GLBEGIN;
  if(streq_ascii(name,"glEnd"))return API_OPENGL32_GLEND;
  if(streq_ascii(name,"glColor3f"))return API_OPENGL32_GLCOLOR3F;
  if(streq_ascii(name,"glColor4f"))return API_OPENGL32_GLCOLOR4F;
  if(streq_ascii(name,"glVertex2f"))return API_OPENGL32_GLVERTEX2F;
  if(streq_ascii(name,"glVertex3f"))return API_OPENGL32_GLVERTEX3F;
  if(streq_ascii(name,"glFlush"))return API_OPENGL32_GLFLUSH;
  if(streq_ascii(name,"glFinish"))return API_OPENGL32_GLFINISH;
  if(streq_ascii(name,"glGetString"))return API_OPENGL32_GLGETSTRING;
  if(streq_ascii(name,"glEnable"))return API_OPENGL32_GLENABLE;
  if(streq_ascii(name,"glDisable"))return API_OPENGL32_GLDISABLE;
  if(streq_ascii(name,"glBlendFunc"))return API_OPENGL32_GLBLENDFUNC;
  if(streq_ascii(name,"glDepthFunc"))return API_OPENGL32_GLDEPTHFUNC;
  if(streq_ascii(name,"glDepthMask"))return API_OPENGL32_GLDEPTHMASK;
  if(streq_ascii(name,"glLineWidth"))return API_OPENGL32_GLLINEWIDTH;
  if(streq_ascii(name,"glPointSize"))return API_OPENGL32_GLPOINTSIZE;
  if(streq_ascii(name,"glTexCoord2f"))return API_OPENGL32_GLTEXCOORD2F;
  if(streq_ascii(name,"glNormal3f"))return API_OPENGL32_GLNORMAL3F;
  if(streq_ascii(name,"glMatrixMode"))return API_OPENGL32_GLMATRIXMODE;
  if(streq_ascii(name,"glLoadIdentity"))return API_OPENGL32_GLLOADIDENTITY;
  if(streq_ascii(name,"glPushMatrix"))return API_OPENGL32_GL_PUSHMATRIX;
  if(streq_ascii(name,"glPopMatrix"))return API_OPENGL32_GL_POPMATRIX;
  if(streq_ascii(name,"glTranslatef"))return API_OPENGL32_GLTRANSLATEF;
  if(streq_ascii(name,"glScalef"))return API_OPENGL32_GLSCALEF;
  if(streq_ascii(name,"glRotatef"))return API_OPENGL32_GLROTATEF;
 }

 if(streq_ascii(dll,"USER32.dll")||streq_ascii(dll,"user32.dll")){
  if(streq_ascii(name,"GetMessageA"))return API_USER32_GETMESSAGEA;
  if(streq_ascii(name,"PeekMessageA"))return API_USER32_PEEKMESSAGEA;
  if(streq_ascii(name,"TranslateMessage"))return API_USER32_TRANSLATEMESSAGE;
  if(streq_ascii(name,"DispatchMessageA"))return API_USER32_DISPATCHMESSAGEA;
  if(streq_ascii(name,"DefWindowProcA"))return API_USER32_DEFWINDOWPROCA;
  if(streq_ascii(name,"PostQuitMessage"))return API_USER32_POSTQUITMESSAGE;
  if(streq_ascii(name,"GetClientRect"))return API_USER32_GETCLIENTRECT;
  if(streq_ascii(name,"InvalidateRect"))return API_USER32_INVALIDATERECT;
  if(streq_ascii(name,"UpdateWindow"))return API_USER32_UPDATEWINDOW;
 }
 if(streq_ascii(dll,"KERNEL32.dll")||streq_ascii(dll,"kernel32.dll")){
  if(streq_ascii(name,"Beep"))return API_KERNEL32_BEEP;
 }
 if(streq_ascii(dll,"KERNEL32.dll")||streq_ascii(dll,"kernel32.dll")){
  if(streq_ascii(name,"CreateFileA"))return API_KERNEL32_CREATEFILEA;
  if(streq_ascii(name,"ReadFile"))return API_KERNEL32_READFILE;
  if(streq_ascii(name,"WriteFile"))return API_KERNEL32_WRITEFILE;
  if(streq_ascii(name,"CloseHandle"))return API_KERNEL32_CLOSEHANDLE;
  if(streq_ascii(name,"SetFilePointer"))return API_KERNEL32_SETFILEPOINTER;
  if(streq_ascii(name,"GetFileSize"))return API_KERNEL32_GETFILESIZE;
  if(streq_ascii(name,"RegOpenKeyExA"))return API_KERNEL32_REGOPENKEYEXA;
  if(streq_ascii(name,"RegCreateKeyExA"))return API_KERNEL32_REGCREATEKEYEXA;
  if(streq_ascii(name,"RegQueryValueExA"))return API_KERNEL32_REGQUERYVALUEEXA;
  if(streq_ascii(name,"RegSetValueExA"))return API_KERNEL32_REGSETVALUEEXA;
  if(streq_ascii(name,"RegCloseKey"))return API_KERNEL32_REGCLOSEKEY;
  if(streq_ascii(name,"RegDeleteValueA"))return API_KERNEL32_REGDELETEVALUEA;
  if(streq_ascii(name,"GetLastError"))return API_KERNEL32_GETLASTERROR;
  if(streq_ascii(name,"SetLastError"))return API_KERNEL32_SETLASTERROR;
 }
 if(streq_ascii(dll,"XWASMCRT.dll")||streq_ascii(dll,"xwasmcrt.dll"))return 0; /* C5 uses direct cdecl API addresses. */
 if(streq_ascii(dll,"ADVAPI32.dll")||streq_ascii(dll,"advapi32.dll")){
  if(streq_ascii(name,"RegOpenKeyExA"))return API_KERNEL32_REGOPENKEYEXA;
  if(streq_ascii(name,"RegCreateKeyExA"))return API_KERNEL32_REGCREATEKEYEXA;
  if(streq_ascii(name,"RegQueryValueExA"))return API_KERNEL32_REGQUERYVALUEEXA;
  if(streq_ascii(name,"RegSetValueExA"))return API_KERNEL32_REGSETVALUEEXA;
  if(streq_ascii(name,"RegCloseKey"))return API_KERNEL32_REGCLOSEKEY;
  if(streq_ascii(name,"RegDeleteValueA"))return API_KERNEL32_REGDELETEVALUEA;
 }
 {uint32_t md=x86_dll_module_for_name(dll);if(md){uint32_t t=x86_dll_get_proc(md,name);if(t)return t;}}
 {int32_t xi=xapi_lookup(dll,name);if(xi>=0)return API_XAPI_BASE+(uint32_t)xi*4u;}
 return 0;
}
static uint32_t opengl_proc_target(uint32_t name){
 if(streq_ascii(name,"wglCreateContext"))return API_OPENGL32_WGLCREATECONTEXT;
 if(streq_ascii(name,"wglDeleteContext"))return API_OPENGL32_WGLDELETECONTEXT;
 if(streq_ascii(name,"wglMakeCurrent"))return API_OPENGL32_WGLMAKECURRENT;
 if(streq_ascii(name,"wglGetCurrentContext"))return API_OPENGL32_WGLGETCURRENTCONTEXT;
 if(streq_ascii(name,"wglShareLists"))return API_OPENGL32_WGLSHARELISTS;
 if(streq_ascii(name,"wglGetProcAddress"))return API_OPENGL32_WGLGETPROCADDRESS;
 if(streq_ascii(name,"glClearColor"))return API_OPENGL32_GLCLEARCOLOR;
 if(streq_ascii(name,"glClear"))return API_OPENGL32_GLCLEAR;
 if(streq_ascii(name,"glViewport"))return API_OPENGL32_GLVIEWPORT;
 if(streq_ascii(name,"glBegin"))return API_OPENGL32_GLBEGIN;
 if(streq_ascii(name,"glEnd"))return API_OPENGL32_GLEND;
 if(streq_ascii(name,"glColor3f"))return API_OPENGL32_GLCOLOR3F;
 if(streq_ascii(name,"glColor4f"))return API_OPENGL32_GLCOLOR4F;
 if(streq_ascii(name,"glVertex2f"))return API_OPENGL32_GLVERTEX2F;
 if(streq_ascii(name,"glVertex3f"))return API_OPENGL32_GLVERTEX3F;
 if(streq_ascii(name,"glFlush"))return API_OPENGL32_GLFLUSH;
 if(streq_ascii(name,"glFinish"))return API_OPENGL32_GLFINISH;
 if(streq_ascii(name,"glGetString"))return API_OPENGL32_GLGETSTRING;
 if(streq_ascii(name,"glEnable"))return API_OPENGL32_GLENABLE;
 if(streq_ascii(name,"glDisable"))return API_OPENGL32_GLDISABLE;
 if(streq_ascii(name,"glBlendFunc"))return API_OPENGL32_GLBLENDFUNC;
 if(streq_ascii(name,"glDepthFunc"))return API_OPENGL32_GLDEPTHFUNC;
 if(streq_ascii(name,"glDepthMask"))return API_OPENGL32_GLDEPTHMASK;
 if(streq_ascii(name,"glLineWidth"))return API_OPENGL32_GLLINEWIDTH;
 if(streq_ascii(name,"glPointSize"))return API_OPENGL32_GLPOINTSIZE;
 if(streq_ascii(name,"glTexCoord2f"))return API_OPENGL32_GLTEXCOORD2F;
 if(streq_ascii(name,"glNormal3f"))return API_OPENGL32_GLNORMAL3F;
 if(streq_ascii(name,"glMatrixMode"))return API_OPENGL32_GLMATRIXMODE;
 if(streq_ascii(name,"glLoadIdentity"))return API_OPENGL32_GLLOADIDENTITY;
 if(streq_ascii(name,"glPushMatrix"))return API_OPENGL32_GL_PUSHMATRIX;
 if(streq_ascii(name,"glPopMatrix"))return API_OPENGL32_GL_POPMATRIX;
 if(streq_ascii(name,"glTranslatef"))return API_OPENGL32_GLTRANSLATEF;
 if(streq_ascii(name,"glScalef"))return API_OPENGL32_GLSCALEF;
 if(streq_ascii(name,"glRotatef"))return API_OPENGL32_GLROTATEF;
 return 0;
}
static uint32_t gl_color_u32(void){
 uint32_t r=(uint32_t)(gl_color_r<0?0:(gl_color_r>1?255:gl_color_r*255.0f));
 uint32_t g=(uint32_t)(gl_color_g<0?0:(gl_color_g>1?255:gl_color_g*255.0f));
 uint32_t b=(uint32_t)(gl_color_b<0?0:(gl_color_b>1?255:gl_color_b*255.0f));
 return r|(g<<8)|(b<<16);
}
static uint32_t gl_clear_u32(void){
 uint32_t r=(uint32_t)(gl_clear_r<0?0:(gl_clear_r>1?255:gl_clear_r*255.0f));
 uint32_t g=(uint32_t)(gl_clear_g<0?0:(gl_clear_g>1?255:gl_clear_g*255.0f));
 uint32_t b=(uint32_t)(gl_clear_b<0?0:(gl_clear_b>1?255:gl_clear_b*255.0f));
 return r|(g<<8)|(b<<16);
}
static int gl_project(float x,float y,int32_t *px,int32_t *py){
 if(!px||!py||gl_viewport_w<=0||gl_viewport_h<=0)return 0;
 *px=gl_viewport_x+(int32_t)(((x+1.0f)*0.5f)*(float)gl_viewport_w);
 *py=gl_viewport_y+(int32_t)(((1.0f-y)*0.5f)*(float)gl_viewport_h);
 return 1;
}
static void gl_draw_triangle(void){
 if(gl_vertex_count<3u)return;
 int32_t x0,y0,x1,y1,x2,y2;
 if(!gl_project(gl_vertices[0][0],gl_vertices[0][1],&x0,&y0))return;
 if(!gl_project(gl_vertices[1][0],gl_vertices[1][1],&x1,&y1))return;
 if(!gl_project(gl_vertices[2][0],gl_vertices[2][1],&x2,&y2))return;
 int32_t minx=x0,maxx=x0,miny=y0,maxy=y0;
 if(x1<minx)minx=x1;if(x2<minx)minx=x2;if(x1>maxx)maxx=x1;if(x2>maxx)maxx=x2;
 if(y1<miny)miny=y1;if(y2<miny)miny=y2;if(y1>maxy)maxy=y1;if(y2>maxy)maxy=y2;
 if(minx<gl_viewport_x)minx=gl_viewport_x;if(miny<gl_viewport_y)miny=gl_viewport_y;
 if(maxx>=gl_viewport_x+gl_viewport_w)maxx=gl_viewport_x+gl_viewport_w-1;
 if(maxy>=gl_viewport_y+gl_viewport_h)maxy=gl_viewport_y+gl_viewport_h-1;
 int32_t area=(x1-x0)*(y2-y0)-(y1-y0)*(x2-x0);
 if(!area)return;
 uint32_t color=gl_color_u32();
 for(int32_t y=miny;y<=maxy;y++)for(int32_t x=minx;x<=maxx;x++){
  int32_t w0=(x1-x0)*(y-y0)-(y1-y0)*(x-x0);
  int32_t w1=(x2-x1)*(y-y1)-(y2-y1)*(x-x1);
  int32_t w2=(x0-x2)*(y-y2)-(y0-y2)*(x-x2);
  if((area>0&&w0>=0&&w1>=0&&w2>=0)||(area<0&&w0<=0&&w1<=0&&w2<=0))z_host_gfx_pixel(x,y,(int32_t)color);
 }
}


static uint32_t call_builtin_impl(uint32_t target){
 if(target>=API_XAPI_BASE&&target<API_XAPI_BASE+xapi_count*4u)return xapi_call((target-API_XAPI_BASE)>>2);
 if(target>=API_SHIM_BASE&&target<API_SHIM_BASE+SHIM_COUNT*4u){
  crt_last_shim_caller=eip;
  crt_last_shim_target=target;
  return shim_call((target-API_SHIM_BASE)>>2);
 }
 if(target==API_C5_MALLOC){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_crt_malloc_impl(rd32(sp+4u));return 1;}
 if(target==API_C5_FREE){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_crt_free_impl(rd32(sp+4u));return 1;}
 if(target==API_C5_STRLEN){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_crt_strlen(rd32(sp+4u));return 1;}
 if(target==API_C5_FS_MOUNT){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_fs_mount_impl_from_guest(rd32(sp+4u),rd32(sp+8u),rd32(sp+12u));return 1;}
 if(target==API_C5_FS_OPEN){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_fs_open_impl_from_guest(rd32(sp+4u),rd32(sp+8u),rd32(sp+12u));return 1;}
 if(target==API_C5_FS_READ){uint32_t sp=regs[R_ESP];uint32_t n=0,ok=x86_fs_read_impl(rd32(sp+4u),rd32(sp+8u),rd32(sp+12u),&n);regs[R_EAX]=ok?n:0xFFFFFFFFu;return 1;}
 if(target==API_C5_FS_CLOSE){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_fs_close_impl(rd32(sp+4u));return 1;}
 if(target==API_C5_REG_CREATE){uint32_t sp=regs[R_ESP],handle=0,disp=0;regs[R_EAX]=x86_reg_create_guest_impl(rd32(sp+4u),rd32(sp+8u),rd32(sp+12u),&handle,&disp);return 1;}
 if(target==API_C5_REG_SET){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_reg_set_guest_impl(rd32(sp+4u),rd32(sp+8u),rd32(sp+12u),rd32(sp+16u),rd32(sp+20u));return 1;}
 if(target==API_C5_REG_CLOSE){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_reg_close_impl(rd32(sp+4u));return 1;}
 if(target==API_GETTICKCOUNT){regs[R_EAX]=1234u;return 1;}
 if(target==API_XWASM_LOG){
  z_host_log(1,(int32_t)regs[R_ECX],(int32_t)regs[R_EDX]);
  return 1;
 }
 if(target==API_VIRTUALALLOC){
  /* Win32 stdcall: lpAddress, dwSize, flAllocationType, flProtect. */
  uint32_t sp=regs[R_ESP];
  uint32_t size=al4(rd32(sp+8u));
  if(!size){regs[R_EAX]=0;regs[R_ESP]+=16u;return 1;}
  uint32_t a=x86_mem_alloc_region(size,X86_MEM_READ|X86_MEM_WRITE,2u);
  if(!a){regs[R_EAX]=0;regs[R_ESP]+=16u;return 1;}
  regs[R_EAX]=a;
  regs[R_ESP]+=16u;
  return 1;
 }
 if(target==API_USER32_CREATEWINDOWEXA){
  /* Win32 stdcall: 12 arguments, width/height are args 6/7. */
  uint32_t sp=regs[R_ESP];
  uint32_t width=rd32(sp+28u),height=rd32(sp+32u);
  if(width<64u||width>1920u)width=640u;
  if(height<64u||height>1080u)height=360u;
  surface_width=width; surface_height=height;
  z_host_gfx_create((int32_t)width,(int32_t)height);
  z_host_gfx_clear(0x00101820);
  z_host_gfx_present();
  regs[R_EAX]=1u; regs[R_ESP]+=48u; return 1;
 }
 if(target==API_USER32_SHOWWINDOW){ regs[R_EAX]=1u; regs[R_ESP]+=8u; return 1; }
 if(target==API_USER32_GETDC){ regs[R_EAX]=1u; regs[R_ESP]+=4u; return 1; }
 if(target==API_USER32_RELEASEDC){ regs[R_EAX]=1u; regs[R_ESP]+=8u; return 1; }
 if(target==API_GDI32_SETPIXEL){
  uint32_t sp=regs[R_ESP]; uint32_t hdc=rd32(sp+4u),x=rd32(sp+8u),y=rd32(sp+12u),color=rd32(sp+16u);
  if(hdc) z_host_gfx_pixel((int32_t)x,(int32_t)y,(int32_t)color); z_host_gfx_present(); regs[R_EAX]=color; regs[R_ESP]+=16u; return 1;
 }
 if(target==API_OPENGL32_WGLSHARELISTS){regs[R_EAX]=1u;regs[R_ESP]+=8u;return 1;}
 if(target==API_OPENGL32_WGLGETPROCADDRESS){uint32_t sp=regs[R_ESP];regs[R_EAX]=opengl_proc_target(rd32(sp+4u));regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_WGLCREATECONTEXT){regs[R_EAX]=gl_context;regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_WGLDELETECONTEXT){uint32_t sp=regs[R_ESP];if(rd32(sp+4u)==gl_current_context)gl_current_context=0;regs[R_EAX]=1u;regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_WGLMAKECURRENT){uint32_t sp=regs[R_ESP];uint32_t hdc=rd32(sp+4u),ctx=rd32(sp+8u);gl_current_context=ctx?ctx:0;if(hdc&&ctx)z_host_gfx_create((int32_t)surface_width,(int32_t)surface_height);regs[R_EAX]=1u;regs[R_ESP]+=8u;return 1;}
 if(target==API_OPENGL32_WGLGETCURRENTCONTEXT){regs[R_EAX]=gl_current_context;return 1;}
 if(target==API_OPENGL32_GLCLEARCOLOR){uint32_t sp=regs[R_ESP];union{uint32_t u;float f;}a,b,d,e;a.u=rd32(sp+4u);b.u=rd32(sp+8u);d.u=rd32(sp+12u);e.u=rd32(sp+16u);gl_clear_r=a.f;gl_clear_g=b.f;gl_clear_b=d.f;gl_clear_a=e.f;regs[R_ESP]+=16u;return 1;}
 if(target==API_OPENGL32_GLCLEAR){uint32_t sp=regs[R_ESP];if(rd32(sp+4u)&0x00004000u)z_host_gfx_clear((int32_t)gl_clear_u32());regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_GLVIEWPORT){uint32_t sp=regs[R_ESP];gl_viewport_x=(int32_t)rd32(sp+4u);gl_viewport_y=(int32_t)rd32(sp+8u);gl_viewport_w=(int32_t)rd32(sp+12u);gl_viewport_h=(int32_t)rd32(sp+16u);regs[R_ESP]+=16u;return 1;}
 if(target==API_OPENGL32_GLBEGIN){uint32_t sp=regs[R_ESP];gl_begin_mode=rd32(sp+4u);gl_vertex_count=0;gl_mode=1;regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_GLEND){gl_mode=0;if(gl_begin_mode==0x0004u)gl_draw_triangle();z_host_gfx_present();return 1;}
 if(target==API_OPENGL32_GLCOLOR3F||target==API_OPENGL32_GLCOLOR4F){uint32_t sp=regs[R_ESP];union{uint32_t u;float f;}a,b,d,e;a.u=rd32(sp+4u);b.u=rd32(sp+8u);d.u=rd32(sp+12u);gl_color_r=a.f;gl_color_g=b.f;gl_color_b=d.f;if(target==API_OPENGL32_GLCOLOR4F){e.u=rd32(sp+16u);gl_color_a=e.f;regs[R_ESP]+=16u;}else regs[R_ESP]+=12u;return 1;}
 if(target==API_OPENGL32_GLVERTEX2F||target==API_OPENGL32_GLVERTEX3F){uint32_t sp=regs[R_ESP];if(gl_mode&&gl_vertex_count<64u){union{uint32_t u;float f;}a,b,d;a.u=rd32(sp+4u);b.u=rd32(sp+8u);d.u=(target==API_OPENGL32_GLVERTEX3F)?rd32(sp+12u):0;gl_vertices[gl_vertex_count][0]=a.f;gl_vertices[gl_vertex_count][1]=b.f;gl_vertices[gl_vertex_count][2]=d.f;gl_vertex_count++;}regs[R_ESP]+=(target==API_OPENGL32_GLVERTEX3F?12u:8u);return 1;}
 if(target==API_OPENGL32_GLFLUSH||target==API_OPENGL32_GLFINISH){z_host_gfx_present();return 1;}
 if(target==API_OPENGL32_GLENABLE||target==API_OPENGL32_GLDISABLE||target==API_OPENGL32_GLDEPTHFUNC||target==API_OPENGL32_GLDEPTHMASK||target==API_OPENGL32_GLMATRIXMODE){regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_GLBLENDFUNC){regs[R_ESP]+=8u;return 1;}
 if(target==API_OPENGL32_GLLINEWIDTH||target==API_OPENGL32_GLPOINTSIZE){regs[R_ESP]+=4u;return 1;}
 if(target==API_OPENGL32_GLTEXCOORD2F){regs[R_ESP]+=8u;return 1;}
 if(target==API_OPENGL32_GLNORMAL3F){regs[R_ESP]+=12u;return 1;}
 if(target==API_OPENGL32_GLLOADIDENTITY||target==API_OPENGL32_GL_PUSHMATRIX||target==API_OPENGL32_GL_POPMATRIX){return 1;}
 if(target==API_OPENGL32_GLTRANSLATEF||target==API_OPENGL32_GLSCALEF){regs[R_ESP]+=12u;return 1;}
 if(target==API_OPENGL32_GLROTATEF){regs[R_ESP]+=16u;return 1;}
 if(target==API_OPENGL32_GLGETSTRING){uint32_t sp=regs[R_ESP],name=rd32(sp+4u);const char *s="XWASM OpenGL";if(name==0x1F00u)s="XWASM";else if(name==0x1F01u)s="XWASM WebGL-compatible renderer";else if(name==0x1F02u)s="1.1 XWASM compatibility";uint32_t p=guest_alloc_raw(64u);if(p){uint32_t i=0;while(s[i]){wr8(p+i,(uint8_t)s[i]);i++;}wr8(p+i,0);}regs[R_EAX]=p;regs[R_ESP]+=4u;return 1;}
 if(target==API_GDI32_SWAPBUFFERS){z_host_gfx_present();regs[R_EAX]=1u;regs[R_ESP]+=4u;return 1;}
 if(target==API_GDI32_CHOOSEPIXELFORMAT){regs[R_EAX]=1u;regs[R_ESP]+=8u;return 1;}
 if(target==API_GDI32_SETPIXELFORMAT){regs[R_EAX]=1u;regs[R_ESP]+=12u;return 1;}
 if(target==API_GDI32_RECTANGLE){
  uint32_t sp=regs[R_ESP]; uint32_t hdc=rd32(sp+4u),left=rd32(sp+8u),top=rd32(sp+12u),right=rd32(sp+16u),bottom=rd32(sp+20u);
  if(hdc) z_host_gfx_rect((int32_t)left,(int32_t)top,(int32_t)right,(int32_t)bottom,0x00FFFFFF); z_host_gfx_present(); regs[R_EAX]=1u; regs[R_ESP]+=20u; return 1;
 }
 if(target==API_USER32_GETMESSAGEA || target==API_USER32_PEEKMESSAGEA){
  /* 32-bit MSG: hwnd, message, wParam, lParam, time, pt.x, pt.y. */
  uint32_t sp=regs[R_ESP],msg=rd32(sp+4u);
  /* PeekMessageA(MSG*, hWnd, min, max, removeMsg): removeMsg is arg 5. */
  uint32_t remove=target==API_USER32_GETMESSAGEA?1u:rd32(sp+20u);
  int32_t got=z_host_input_poll((int32_t)msg,(int32_t)remove);
  if(got>0){
   message_count++; message_last=rd32(msg+4u);
   if(message_last==0x0012u)message_quit=1;
   regs[R_EAX]=1u;
  }else{
   regs[R_EAX]=0u;
  }
  regs[R_ESP]+=20u;
  return 1;
 }
 if(target==API_USER32_TRANSLATEMESSAGE){
  regs[R_EAX]=1u; regs[R_ESP]+=4u; return 1;
 }
 if(target==API_USER32_DISPATCHMESSAGEA){
  uint32_t sp=regs[R_ESP],msg=rd32(sp+4u),type=msg?rd32(msg+4u):0;
  if(msg){
   uint32_t lp=rd32(msg+12u);
   if(type==0x0200u) mouse_moves++;
   else if(type==0x0204u) mouse_right_clicks++;
   else if(type==0x0207u) mouse_middle_clicks++;
   if(type==0x0201u){
    int32_t x=(int16_t)(lp&0xFFFFu),y=(int16_t)((lp>>16)&0xFFFFu);
    mouse_clicks++;
    z_host_gfx_rect(x-4,y-4,x+5,y+5,0x0000FF00);
    z_host_gfx_pixel(x,y,0x00FFFFFF);
    z_host_gfx_present();
    z_host_audio_beep(880,70);
   }
  }
  regs[R_EAX]=0u; regs[R_ESP]+=4u; return 1;
 }
 if(target==API_USER32_DEFWINDOWPROCA){
  regs[R_EAX]=0u; regs[R_ESP]+=16u; return 1;
 }
 if(target==API_USER32_POSTQUITMESSAGE){
  message_quit=1; z_host_input_quit(); regs[R_ESP]+=4u; return 1;
 }
 if(target==API_USER32_GETCLIENTRECT){
  uint32_t sp=regs[R_ESP],rect=rd32(sp+8u);
  if(rect){wr32(rect,0);wr32(rect+4u,0);wr32(rect+8u,surface_width);wr32(rect+12u,surface_height);}
  regs[R_EAX]=rect?1u:0u; regs[R_ESP]+=8u; return 1;
 }
 if(target==API_USER32_INVALIDATERECT){
  regs[R_EAX]=1u; regs[R_ESP]+=12u; z_host_gfx_present(); return 1;
 }
 if(target==API_USER32_UPDATEWINDOW){
  regs[R_EAX]=1u; regs[R_ESP]+=4u; z_host_gfx_present(); return 1;
 }
 if(target==API_KERNEL32_CREATEFILEA){
  uint32_t sp=regs[R_ESP],path=rd32(sp+4u),access=rd32(sp+8u),creation=rd32(sp+20u);char raw[X86_FS_MAX_PATH];
  if(!x86_fs_guest_string(path,raw,sizeof(raw))){regs[R_EAX]=0xFFFFFFFFu;regs[R_ESP]+=28u;return 1;}
  uint32_t a=(access&0x40000000u)?X86_FS_ACCESS_WRITE:X86_FS_ACCESS_READ;
  if((access&0xC0000000u)==0xC0000000u)a=X86_FS_ACCESS_READ|X86_FS_ACCESS_WRITE;
  uint32_t flags=(creation==2u||creation==3u)?X86_FS_OPEN_CREATE:0u;if(creation==2u||creation==4u)flags|=X86_FS_OPEN_TRUNCATE;
  regs[R_EAX]=x86_fs_open_impl(raw,a,flags);if(!regs[R_EAX])regs[R_EAX]=0xFFFFFFFFu;regs[R_ESP]+=28u;return 1;
 }
 if(target==API_KERNEL32_READFILE){
  uint32_t sp=regs[R_ESP],h=rd32(sp+4u),dst=rd32(sp+8u),size=rd32(sp+12u),out=rd32(sp+16u),n=0;
  regs[R_EAX]=x86_fs_read_impl(h,dst,size,&n);if(out&&x86_mem_region_find(out,4u,X86_MEM_WRITE))wr32(out,n);regs[R_ESP]+=20u;return 1;
 }
 if(target==API_KERNEL32_WRITEFILE){
  uint32_t sp=regs[R_ESP],h=rd32(sp+4u),src=rd32(sp+8u),size=rd32(sp+12u),out=rd32(sp+16u),n=0;
  regs[R_EAX]=x86_fs_write_impl(h,src,size,&n);if(out&&x86_mem_region_find(out,4u,X86_MEM_WRITE))wr32(out,n);regs[R_ESP]+=20u;return 1;
 }
 if(target==API_KERNEL32_CLOSEHANDLE){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_fs_close_impl(rd32(sp+4u));regs[R_ESP]+=4u;return 1;}
 if(target==API_KERNEL32_SETFILEPOINTER){uint32_t sp=regs[R_ESP],h=rd32(sp+4u),distance=rd32(sp+8u),origin=rd32(sp+16u);regs[R_EAX]=x86_fs_seek_impl(h,(int32_t)distance,origin);regs[R_ESP]+=16u;return 1;}
 if(target==API_KERNEL32_GETFILESIZE){uint32_t sp=regs[R_ESP],h=rd32(sp+4u),high=rd32(sp+8u),size=x86_fs_size_impl(h);if(high&&x86_mem_region_find(high,4u,X86_MEM_WRITE))wr32(high,0);regs[R_EAX]=size;regs[R_ESP]+=8u;return 1;}
 if(target==API_KERNEL32_REGOPENKEYEXA){
  uint32_t sp=regs[R_ESP],parent=rd32(sp+4u),sub=rd32(sp+8u),out=rd32(sp+20u);char raw[X86_REG_MAX_PATH];uint32_t handle=0,result=0;
  if(sub&&!x86_fs_guest_string(sub,raw,sizeof(raw)))result=X86_REG_ERROR_INVALID_PARAMETER;else result=x86_reg_open_impl(parent,sub?raw:"",&handle);
  if(result==X86_REG_ERROR_SUCCESS&&(!out||!x86_mem_region_find(out,4u,X86_MEM_WRITE)))result=X86_REG_ERROR_INVALID_PARAMETER;
  if(result==X86_REG_ERROR_SUCCESS)wr32(out,handle);
  regs[R_EAX]=result;regs[R_ESP]+=20u;return 1;
 }
 if(target==API_KERNEL32_REGCREATEKEYEXA){
  uint32_t sp=regs[R_ESP],parent=rd32(sp+4u),sub=rd32(sp+8u),out=rd32(sp+32u),disp_ptr=rd32(sp+36u);char raw[X86_REG_MAX_PATH];uint32_t handle=0,disp=0,result=0;
  if(sub&&!x86_fs_guest_string(sub,raw,sizeof(raw)))result=X86_REG_ERROR_INVALID_PARAMETER;
  else result=x86_reg_create_impl(parent,sub?raw:"",&handle,&disp);
  if(result==X86_REG_ERROR_SUCCESS&&out&&x86_mem_region_find(out,4u,X86_MEM_WRITE))wr32(out,handle);
  if(result==X86_REG_ERROR_SUCCESS&&disp_ptr&&x86_mem_region_find(disp_ptr,4u,X86_MEM_WRITE))wr32(disp_ptr,disp);
  regs[R_EAX]=result;regs[R_ESP]+=36u;return 1;
 }
 if(target==API_KERNEL32_REGQUERYVALUEEXA){
  uint32_t sp=regs[R_ESP],handle=rd32(sp+4u),name=rd32(sp+8u),type_ptr=rd32(sp+16u),data=rd32(sp+20u),size_ptr=rd32(sp+24u);char raw[X86_REG_MAX_VALUE_NAME];uint32_t type=0,size=0,result;
  if(name&&!x86_fs_guest_string(name,raw,sizeof(raw))){result=X86_REG_ERROR_INVALID_PARAMETER;regs[R_EAX]=result;regs[R_ESP]+=24u;return 1;}
  if(size_ptr&&!x86_mem_region_find(size_ptr,4u,X86_MEM_READ|X86_MEM_WRITE)){result=X86_REG_ERROR_INVALID_PARAMETER;regs[R_EAX]=result;regs[R_ESP]+=24u;return 1;}
  if(size_ptr)size=rd32(size_ptr);
  result=x86_reg_query_value_impl(handle,name?raw:"",&type,data?((uint8_t*)(uintptr_t)data):0,&size);
  if(type_ptr&&x86_mem_region_find(type_ptr,4u,X86_MEM_WRITE))wr32(type_ptr,type);
  if(size_ptr&&x86_mem_region_find(size_ptr,4u,X86_MEM_WRITE))wr32(size_ptr,size);
  regs[R_EAX]=result;regs[R_ESP]+=24u;return 1;
 }
 if(target==API_KERNEL32_REGSETVALUEEXA){
  uint32_t sp=regs[R_ESP],handle=rd32(sp+4u),name=rd32(sp+8u),type=rd32(sp+16u),data=rd32(sp+20u),size=rd32(sp+24u);char raw[X86_REG_MAX_VALUE_NAME];
  if(name&&!x86_fs_guest_string(name,raw,sizeof(raw))){regs[R_EAX]=X86_REG_ERROR_INVALID_PARAMETER;regs[R_ESP]+=24u;return 1;}
  if(size&&!x86_mem_region_find(data,size,X86_MEM_READ)){regs[R_EAX]=X86_REG_ERROR_INVALID_PARAMETER;regs[R_ESP]+=24u;return 1;}
  uint8_t tmp[X86_REG_MAX_VALUE_DATA];if(size>sizeof(tmp)){regs[R_EAX]=X86_REG_ERROR_INVALID_PARAMETER;regs[R_ESP]+=24u;return 1;}for(uint32_t i=0;i<size;i++)tmp[i]=MEM8(data+i);
  uint32_t result=x86_reg_set_value_impl(handle,name?raw:"",type,tmp,size);regs[R_EAX]=result;regs[R_ESP]+=24u;return 1;
 }
 if(target==API_KERNEL32_REGCLOSEKEY){uint32_t sp=regs[R_ESP];regs[R_EAX]=x86_reg_close_impl(rd32(sp+4u));regs[R_ESP]+=4u;return 1;}
 if(target==API_KERNEL32_REGDELETEVALUEA){
  uint32_t sp=regs[R_ESP],handle=rd32(sp+4u),name=rd32(sp+8u);char raw[X86_REG_MAX_VALUE_NAME];
  if(name&&!x86_fs_guest_string(name,raw,sizeof(raw))){regs[R_EAX]=X86_REG_ERROR_INVALID_PARAMETER;regs[R_ESP]+=8u;return 1;}
  regs[R_EAX]=x86_reg_delete_value_impl(handle,name?raw:"");regs[R_ESP]+=8u;return 1;
 }
 if(target==API_KERNEL32_GETLASTERROR){regs[R_EAX]=crt_last_error;return 1;}
 if(target==API_KERNEL32_SETLASTERROR){uint32_t sp=regs[R_ESP];crt_last_error=rd32(sp+4u);regs[R_ESP]+=4u;return 1;}
 if(target==API_KERNEL32_BEEP){
  uint32_t sp=regs[R_ESP],freq=rd32(sp+4u),duration=rd32(sp+8u);
  z_host_audio_beep((int32_t)freq,(int32_t)duration);
  regs[R_EAX]=1u; regs[R_ESP]+=8u; return 1;
 }
 if(target==API_VIRTUALFREE){
  /* Win32 stdcall: lpAddress, dwSize, dwFreeType. */
  uint32_t sp=regs[R_ESP];
  uint32_t address=rd32(sp+4u),size=rd32(sp+8u),free_type=rd32(sp+12u);
  (void)size;
  (void)free_type;
  regs[R_EAX]=(address!=0)?1u:0u;
  if(address!=0)x86_mem_free_region(address);
  regs[R_ESP]+=12u;
  return 1;
 }
 return 0;
}

/* ---- API call log: the last X86_APILOG_DEPTH calls into host-implemented imports ---------------- */
#define X86_APILOG_DEPTH 128u
static uint32_t apilog_target[X86_APILOG_DEPTH],apilog_caller[X86_APILOG_DEPTH],apilog_arg[X86_APILOG_DEPTH][4],apilog_ret[X86_APILOG_DEPTH],apilog_step[X86_APILOG_DEPTH];
static uint32_t apilog_count=0;
static uint32_t call_builtin(uint32_t target){
 uint32_t sp=regs[R_ESP],a[4]={0,0,0,0},caller=0;
 if(x86_mem_region_find(sp,20u,X86_MEM_READ)){caller=rd32(sp);for(uint32_t i=0;i<4u;i++)a[i]=rd32(sp+4u+i*4u);}
 uint32_t r=call_builtin_impl(target);
 if(r){
  uint32_t k=apilog_count%X86_APILOG_DEPTH;
  apilog_target[k]=target;apilog_caller[k]=caller;apilog_ret[k]=regs[R_EAX];apilog_step[k]=steps;
  for(uint32_t i=0;i<4u;i++)apilog_arg[k][i]=a[i];
  apilog_count++;
 }
 return r;
}

static uint16_t rd16(uint32_t p){return (uint16_t)MEM8(p)|((uint16_t)MEM8(p+1)<<8);}
static uint32_t rd32(uint32_t p){return (uint32_t)MEM8(p)|((uint32_t)MEM8(p+1)<<8)|((uint32_t)MEM8(p+2)<<16)|((uint32_t)MEM8(p+3)<<24);}
static void wr32(uint32_t p,uint32_t v){MEM8(p)=(uint8_t)v;MEM8(p+1)=(uint8_t)(v>>8);MEM8(p+2)=(uint8_t)(v>>16);MEM8(p+3)=(uint8_t)(v>>24);}
static void wr16(uint32_t p,uint16_t v){MEM8(p)=(uint8_t)v;MEM8(p+1)=(uint8_t)(v>>8);}
static void wr8(uint32_t p,uint8_t v){MEM8(p)=v;}
static void copy_bytes(uint32_t d,uint32_t s,uint32_t n){for(uint32_t i=0;i<n;i++)wr8(d+i,MEM8(s+i));}
static void loglit(const char*s){uint32_t p=heap;while(*s)wr8(p++,(uint8_t)*s++);z_host_log(1,(int32_t)heap,(int32_t)(p-heap));heap=al4(p+1);}
static void loghex(const char*s,uint32_t v){uint32_t p=heap;while(*s)wr8(p++,(uint8_t)*s++);wr8(p++,'0');wr8(p++,'x');for(int i=7;i>=0;i--){uint8_t x=(v>>(i*4))&15u;wr8(p++,(uint8_t)(x<10?'0'+x:'A'+x-10));}z_host_log(1,(int32_t)heap,(int32_t)(p-heap));heap=al4(p+1);}

static void set_logic_flags(uint32_t v){
 uint32_t p=v; p^=p>>4; p^=p>>2; p^=p>>1;
 eflags=(eflags&~(CF|PF|AF|ZF|SF|OF))|((p&1u)==0?PF:0)|(v==0?ZF:0)|((v&0x80000000u)?SF:0);
}
static uint32_t parity_even8(uint32_t v){v&=0xFFu;v^=v>>4;v^=v>>2;v^=v>>1;return (v&1u)==0u;}
static void set_logic_flags_width(uint32_t v,uint32_t bits){uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu),sign=1u<<(bits-1u);v&=mask;uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);if(parity_even8(v))f|=PF;if(v==0)f|=ZF;if(v&sign)f|=SF;eflags=f;}
static void set_add_flags_width(uint32_t a,uint32_t b,uint32_t r,uint32_t bits){uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu),sign=1u<<(bits-1u);a&=mask;b&=mask;r&=mask;uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);if((uint64_t)a+(uint64_t)b>mask)f|=CF;if(((a&0xFu)+(b&0xFu))>0xFu)f|=AF;if(parity_even8(r))f|=PF;if(!r)f|=ZF;if(r&sign)f|=SF;if(((~(a^b))&(a^r)&sign)!=0)f|=OF;eflags=f;}
static void set_adc_flags_width(uint32_t a,uint32_t b,uint32_t cin,uint32_t r,uint32_t bits){uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu),sign=1u<<(bits-1u);a&=mask;b&=mask;r&=mask;uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);if((uint64_t)a+(uint64_t)b+cin>mask)f|=CF;if(((a&0xFu)+(b&0xFu)+cin)>0xFu)f|=AF;if(parity_even8(r))f|=PF;if(!r)f|=ZF;if(r&sign)f|=SF;uint32_t bb=(b+cin)&mask;if(((~(a^bb))&(a^r)&sign)!=0)f|=OF;eflags=f;}
static void set_sbb_flags_width(uint32_t a,uint32_t b,uint32_t bin,uint32_t r,uint32_t bits){uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu),sign=1u<<(bits-1u);a&=mask;b&=mask;r&=mask;uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);uint32_t bb=b+bin;if((uint64_t)a<(uint64_t)bb)f|=CF;if((a&0xFu)<((b&0xFu)+bin))f|=AF;if(parity_even8(r))f|=PF;if(!r)f|=ZF;if(r&sign)f|=SF;bb&=mask;if(((a^bb)&(a^r)&sign)!=0)f|=OF;eflags=f;}
static void set_add_flags(uint32_t a,uint32_t b,uint32_t r){
 uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);
 if(r<a)f|=CF;
 if(((a&0xFu)+(b&0xFu))>0xFu)f|=AF;
 if(parity_even8(r))f|=PF;
 if(r==0)f|=ZF;
 if(r&0x80000000u)f|=SF;
 if(((~(a^b))&(a^r)&0x80000000u)!=0)f|=OF;
 eflags=f;
}
static void set_sub_flags(uint32_t a,uint32_t b,uint32_t r){
 uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);
 if(a<b)f|=CF;
 if((a&0xFu)<(b&0xFu))f|=AF;
 if(parity_even8(r))f|=PF;
 if(r==0)f|=ZF;
 if(r&0x80000000u)f|=SF;
 if(((a^b)&(a^r)&0x80000000u)!=0)f|=OF;
 eflags=f;
}
static void set_adc_flags(uint32_t a,uint32_t b,uint32_t cin,uint32_t r){
 uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF),bb=b+cin;
 if(r<a || (cin && r==a))f|=CF;
 if(((a&0xFu)+(b&0xFu)+cin)>0xFu)f|=AF;
 if(parity_even8(r))f|=PF;
 if(r==0)f|=ZF;
 if(r&0x80000000u)f|=SF;
 if(((~(a^bb))&(a^r)&0x80000000u)!=0)f|=OF;
 eflags=f;
}
static void set_sbb_flags(uint32_t a,uint32_t b,uint32_t bin,uint32_t r){
 uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF),bb=b+bin;
 if(a<bb || bb<b)f|=CF;
 if((a&0xFu)<((b&0xFu)+bin))f|=AF;
 if(parity_even8(r))f|=PF;
 if(r==0)f|=ZF;
 if(r&0x80000000u)f|=SF;
 if(((a^bb)&(a^r)&0x80000000u)!=0)f|=OF;
 eflags=f;
}
static void set_sub_flags_width(uint32_t a,uint32_t b,uint32_t r,uint32_t bits){
 uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu),sign=1u<<(bits-1u);
 a&=mask;b&=mask;r&=mask;uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);
 if(a<b)f|=CF;if((a&0xFu)<(b&0xFu))f|=AF;if(parity_even8(r))f|=PF;if(r==0)f|=ZF;if(r&sign)f|=SF;if(((a^b)&(a^r)&sign)!=0)f|=OF;eflags=f;
}
static uint8_t reg8_read(uint32_t r){uint32_t i=r&7u;return (uint8_t)(i<4u?regs[i]:(regs[i-4u]>>8));}
static void reg8_write(uint32_t r,uint8_t v){uint32_t i=r&7u;if(i<4u)regs[i]=(regs[i]&~0xFFu)|v;else{uint32_t q=i-4u;regs[q]=(regs[q]&~0xFF00u)|((uint32_t)v<<8);}}
static uint16_t reg16_read(uint32_t r){return (uint16_t)regs[r&7u];}
static void reg16_write(uint32_t r,uint16_t v){uint32_t i=r&7u;regs[i]=(regs[i]&~0xFFFFu)|v;}
static uint8_t modrm_read8(uint8_t m,uint32_t *ip){uint32_t ea=0;if(!modrm_ea(m,ip,&ea))return reg8_read(m&7);return MEM8(ea);}
static uint16_t modrm_read16(uint8_t m,uint32_t *ip){uint32_t ea=0;if(!modrm_ea(m,ip,&ea))return reg16_read(m&7);return rd16(ea);}
static void modrm_write16(uint8_t m,uint32_t *ip,uint16_t v){uint32_t ea=0;if(!modrm_ea(m,ip,&ea)){reg16_write(m&7,v);return;}wr32(ea,(rd32(ea)&0xFFFF0000u)|v);}
static void modrm_write8(uint8_t m,uint32_t *ip,uint8_t v){uint32_t ea=0;if(!modrm_ea(m,ip,&ea)){reg8_write(m&7,v);return;}wr8(ea,v);}
static void string_step(uint8_t op){
 uint32_t width=(op==0xA4||op==0xA6||op==0xAC||op==0xAE||op==0xAA)?1u:(decoded_operand16?2u:4u),si=regs[R_ESI],di=regs[R_EDI],step=(eflags&DF)?(uint32_t)(-(int32_t)width):width;
 if(op==0xA4||op==0xA5){for(uint32_t i=0;i<width;i++)wr8(di+i,MEM8(si+i));regs[R_ESI]+=step;regs[R_EDI]+=step;}
 else if(op==0xA6||op==0xA7){uint32_t a=width==1?MEM8(si):(width==2?rd16(si):rd32(si)),b=width==1?MEM8(di):(width==2?rd16(di):rd32(di));set_sub_flags_width(a,b,a-b,width*8u);regs[R_ESI]+=step;regs[R_EDI]+=step;}
 else if(op==0xAA||op==0xAB){uint32_t v=width==1?(regs[R_EAX]&0xFFu):(width==2?(regs[R_EAX]&0xFFFFu):regs[R_EAX]);for(uint32_t i=0;i<width;i++)wr8(di+i,(uint8_t)(v>>(8u*i)));regs[R_EDI]+=step;}
 else if(op==0xAC||op==0xAD){uint32_t v=width==1?MEM8(si):(width==2?rd16(si):rd32(si));if(width==1)reg8_write(0,(uint8_t)v);else if(width==2)reg16_write(0,(uint16_t)v);else regs[R_EAX]=v;regs[R_ESI]+=step;}
 else if(op==0xAE||op==0xAF){uint32_t a=width==1?(regs[R_EAX]&0xFFu):(width==2?(regs[R_EAX]&0xFFFFu):regs[R_EAX]),b=width==1?MEM8(di):(width==2?rd16(di):rd32(di));set_sub_flags_width(a,b,a-b,width*8u);regs[R_EDI]+=step;}
}
static void string_execute(uint8_t op){uint32_t repeat=(decoded_prefixes&(X86_PREFIX_REP|X86_PREFIX_REPNZ))?1u:0u;if(!repeat){string_step(op);return;}uint32_t count=regs[R_ECX];while(count){string_step(op);count--;regs[R_ECX]=count;if((op==0xA6||op==0xA7||op==0xAE||op==0xAF)){if((decoded_prefixes&X86_PREFIX_REP)&&!(eflags&ZF))break;if((decoded_prefixes&X86_PREFIX_REPNZ)&&(eflags&ZF))break;}}}
static void set_rotate_flags(uint32_t r,uint32_t cf,uint32_t of_valid,uint32_t of){
 eflags=(eflags&~(CF|OF))|(cf?CF:0u);
 if(of_valid)eflags=(eflags&~OF)|(of?OF:0u);
}
static void set_shift_flags(uint32_t v,uint32_t cf,int of_valid,uint32_t of){
 uint32_t keep=eflags&(CF|OF);
 eflags=(eflags&~(CF|PF|ZF|SF|OF))|((v==0)?ZF:0)|((v&0x80000000u)?SF:0);
 uint32_t p=v; p^=p>>4; p^=p>>2; p^=p>>1;
 if((p&1u)==0)eflags|=PF;
 if(cf)eflags|=CF;
 if(of_valid&&of)eflags|=OF;
 else if(of_valid)eflags&=~OF;
 else eflags=(eflags&~OF)|(keep&OF);
}
static int cond(uint8_t op){
 switch(op){
  case 0xD8:case 0xD9:case 0xDC:case 0xDD:case 0xDE:{uint32_t ip=eip;int r=cpu_step_x87(op,&ip);if(r<0)return r;eip=ip;return 0;}
  case 0x70:return (eflags&OF)!=0; /* JO */
  case 0x71:return (eflags&OF)==0; /* JNO */
  case 0x72:return (eflags&CF)!=0; /* JB/JC */
  case 0x73:return (eflags&CF)==0; /* JAE/JNC */
  case 0x74:return (eflags&ZF)!=0; /* JE/JZ */
  case 0x75:return (eflags&ZF)==0; /* JNE/JNZ */
  case 0x76:return (eflags&CF)!=0||(eflags&ZF)!=0; /* JBE */
  case 0x77:return (eflags&CF)==0&&(eflags&ZF)==0; /* JA */
  case 0x78:return (eflags&SF)!=0; /* JS */
  case 0x79:return (eflags&SF)==0; /* JNS */
  case 0x7A:return (eflags&PF)!=0; /* JP/JPE */
  case 0x7B:return (eflags&PF)==0; /* JNP/JPO */
  case 0x7C:return ((eflags&SF)!=0)!=((eflags&OF)!=0); /* JL */
  case 0x7D:return ((eflags&SF)!=0)==((eflags&OF)!=0); /* JGE */
  case 0x7E:return (eflags&ZF)!=0||(((eflags&SF)!=0)!=((eflags&OF)!=0)); /* JLE */
  case 0x7F:return (eflags&ZF)==0&&(((eflags&SF)!=0)==((eflags&OF)!=0)); /* JG */
  default:return 0;
 }
}
static uint32_t x86_segment_base(void){
 if(decoded_prefixes&0x40u)return x86_fs_base;
 if(decoded_prefixes&0x80u)return x86_gs_base;
 return 0;
}
static int modrm_ea(uint8_t m,uint32_t *ip,uint32_t *ea){
 uint8_t mod=m>>6,rm=m&7;
 if(mod==3)return 0;
 uint32_t base=0,index=0,scale=1;
 if(rm==4){
  uint8_t sib=MEM8((*ip)++);
  uint8_t ss=sib>>6,si=(sib>>3)&7,sb=sib&7;
  scale=1u<<ss;
  if(si!=4)index=regs[si]*scale;
  if(sb==5&&mod==0)base=rd32(*ip),*ip+=4;
  else base=regs[sb];
 }else if(rm==5&&mod==0){
  base=rd32(*ip);*ip+=4;
 }else{
  base=regs[rm];
 }
 if(mod==1){int8_t d=(int8_t)MEM8((*ip)++);base+=(int32_t)d;}
 else if(mod==2){int32_t d=(int32_t)rd32(*ip);*ip+=4;base+=(uint32_t)d;}
 *ea=base+index+x86_segment_base(); return 1;
}
/* ModR/M memory operands must stay inside a registered guest region.
 * Raw WASM bounds alone are insufficient: a guest pointer such as 0x10 can
 * otherwise read the runtime's linear-memory metadata and later poison ESP. */
static void x86_note_operand_fault(uint32_t address,uint32_t size,uint32_t kind){
 x86_mem_faults++;
 x86_last_fault_address=address;
 x86_last_fault_size=size;
 x86_last_fault_kind=kind;
 x86_last_fault_eip=eip;
 x86_last_fault_opcode=MEM8(eip);
 if(x86_first_fault_count==0u){
  x86_first_fault_eip=eip;
  x86_first_fault_opcode=MEM8(eip);
  x86_first_fault_modrm=0u;
 }
 x86_first_fault_count++;
 cpu_error=0xE100u|kind;
}
static uint32_t modrm_read32(uint8_t m,uint32_t *ip){
 uint32_t ea=0;
 if(!modrm_ea(m,ip,&ea))return regs[m&7];
 if(!x86_mem_region_find(ea,4u,X86_MEM_READ)){
  x86_note_operand_fault(ea,4u,1u);
  return 0u;
 }
 return rd32(ea);
}
static void modrm_write32(uint8_t m,uint32_t *ip,uint32_t v){
 uint32_t ea=0;
 if(!modrm_ea(m,ip,&ea)){regs[m&7]=v;return;}
 if(!x86_mem_region_find(ea,4u,X86_MEM_WRITE)){
  x86_note_operand_fault(ea,4u,2u);
  return;
 }
 wr32(ea,v);
}

/* C0 stack/ABI foundation. IA-32 CALL/RET/PUSH/POP must operate on the
 * guest stack region, not merely on raw WASM addresses. */
static int x86_stack_push32(uint32_t v){
 uint32_t next=regs[R_ESP]-4u;
 if(next>regs[R_ESP]||!x86_mem_region_find(next,4u,X86_MEM_WRITE)){x86_mem_faults++;x86_last_stack_fault_esp=next;x86_last_stack_fault_eip=eip;x86_last_stack_fault_kind=1u;cpu_error=0xE001u;return 0;}
 regs[R_ESP]=next;wr32(next,v);return 1;
}
static int x86_stack_pop32(uint32_t *v){
 uint32_t sp=regs[R_ESP];
 if(!x86_mem_region_find(sp,4u,X86_MEM_READ)){x86_mem_faults++;x86_last_stack_fault_esp=sp;x86_last_stack_fault_eip=eip;x86_last_stack_fault_kind=2u;cpu_error=0xE002u;return 0;}
 *v=rd32(sp);regs[R_ESP]=sp+4u;return 1;
}
static int x86_stack_discard(uint32_t n){
 uint32_t sp=regs[R_ESP],next=sp+n;
 if(next<sp||!x86_mem_region_find(sp,n,X86_MEM_READ)){x86_mem_faults++;x86_last_stack_fault_esp=sp;x86_last_stack_fault_eip=eip;x86_last_stack_fault_kind=3u;cpu_error=0xE003u;return 0;}
 regs[R_ESP]=next;return 1;
}

static uint16_t x87_control=0x037Fu; /* 8087-compatible reset control word */
static uint16_t x87_status=0;
#define X87_TRACE_DEPTH 128u
static uint32_t x87_trace_count=0,x87_trace_head=0;
static uint32_t x87_trace_eip[X87_TRACE_DEPTH],x87_trace_opcode[X87_TRACE_DEPTH],x87_trace_modrm[X87_TRACE_DEPTH];
static uint32_t x87_trace_count_before[X87_TRACE_DEPTH],x87_trace_count_after[X87_TRACE_DEPTH];
static uint16_t x87_trace_status_before[X87_TRACE_DEPTH],x87_trace_status_after[X87_TRACE_DEPTH];
static uint32_t x87_last_eip=0,x87_last_opcode=0,x87_last_modrm=0;
static uint32_t x87_last_count_before=0,x87_last_count_after=0;
static uint16_t x87_last_status_before=0,x87_last_status_after=0;
static uint32_t x87_last_fault_eip=0,x87_last_fault_opcode=0,x87_last_fault_modrm=0;
static uint32_t x87_last_fault_count=0;
static void x87_trace_reset(void){
 x87_trace_count=0;x87_trace_head=0;
 x87_last_eip=x87_last_opcode=x87_last_modrm=0;
 x87_last_count_before=x87_last_count_after=0;
 x87_last_status_before=x87_last_status_after=0;
 x87_last_fault_eip=x87_last_fault_opcode=x87_last_fault_modrm=0;
 x87_last_fault_count=0;
}
static void x87_trace_begin(uint32_t at,uint8_t op,uint8_t m){
 if(x87_trace_count){
  uint32_t prev=(x87_trace_head+X87_TRACE_DEPTH-1u)%X87_TRACE_DEPTH;
  x87_trace_count_after[prev]=x87_count;
  x87_trace_status_after[prev]=x87_status;
  x87_last_count_after=x87_count;
  x87_last_status_after=x87_status;
 }
 uint32_t i=x87_trace_head%X87_TRACE_DEPTH;
 x87_trace_eip[i]=at;x87_trace_opcode[i]=op;x87_trace_modrm[i]=m;
 x87_trace_count_before[i]=x87_count;x87_trace_status_before[i]=x87_status;
 x87_last_eip=at;x87_last_opcode=op;x87_last_modrm=m;
 x87_last_count_before=x87_count;x87_last_status_before=x87_status;
 x87_trace_head=(x87_trace_head+1u)%X87_TRACE_DEPTH;
 if(x87_trace_count<X87_TRACE_DEPTH)x87_trace_count++;
}
static void x87_trace_end(int rc){
 uint32_t i=(x87_trace_head+X87_TRACE_DEPTH-1u)%X87_TRACE_DEPTH;
 x87_trace_count_after[i]=x87_count;x87_trace_status_after[i]=x87_status;
 x87_last_count_after=x87_count;x87_last_status_after=x87_status;
 if(rc<0){
  x87_last_fault_eip=x87_last_eip;x87_last_fault_opcode=x87_last_opcode;
  x87_last_fault_modrm=x87_last_modrm;x87_last_fault_count=x87_last_count_before;
 }
}


#define X87_C0 0x0100u
#define X87_C1 0x0200u
#define X87_C2 0x0400u
#define X87_C3 0x4000u

static int x87_is_nan(double v){
 union{uint64_t u;double d;}x;x.d=v;
 return ((x.u>>52)&0x7FFu)==0x7FFu && (x.u&0x000FFFFFFFFFFFFFull)!=0;
}
static int x87_is_inf(double v){
 union{uint64_t u;double d;}x;x.d=v;
 return ((x.u>>52)&0x7FFu)==0x7FFu && (x.u&0x000FFFFFFFFFFFFFull)==0;
}
static void x87_set_compare(double a,double b){
 x87_status&=~(X87_C0|X87_C1|X87_C2|X87_C3);
 if(x87_is_nan(a)||x87_is_nan(b)){x87_status|=X87_C0|X87_C2|X87_C3;return;}
 if(a==b)x87_status|=X87_C3;
 else if(a<b)x87_status|=X87_C0;
}
static int x87_valid_reg(uint8_t r){
 if(r>=x87_count){
  cpu_error=0xD802u;
  x87_last_fault_eip=x87_last_eip;
  x87_last_fault_opcode=x87_last_opcode;
  x87_last_fault_modrm=x87_last_modrm;
  x87_last_fault_count=x87_last_count_before;
  return 0;
 }
 return 1;
}
static int x87_need_top(void){return x87_valid_reg(0);}
static int x87_push(double v){
 if(x87_count>=8u){x87_status|=X87_C1;cpu_error=0xD801u;return 0;}
 for(uint32_t i=x87_count;i>0u;i--)x87_stack[i]=x87_stack[i-1u];
 x87_stack[0]=v;x87_count++;x87_status&=~X87_C1;return 1;
}
static int x87_pop(void){
 if(!x87_count){
  cpu_error=0xD802u;x87_status|=X87_C1;
  x87_last_fault_eip=x87_last_eip;
  x87_last_fault_opcode=x87_last_opcode;
  x87_last_fault_modrm=x87_last_modrm;
  x87_last_fault_count=x87_last_count_before;
  return 0;
 }
 for(uint32_t i=1;i<x87_count;i++)x87_stack[i-1u]=x87_stack[i];
 x87_count--;x87_status&=~X87_C1;return 1;
}
static int x87_fxch(uint8_t r){
 if(!x87_valid_reg(r))return 0;
 double t=x87_stack[0];x87_stack[0]=x87_stack[r];x87_stack[r]=t;return 1;
}
static void x87_rotate_top(int direction){
 /* Logical equivalent of FINCSTP/FDECSTP for our compact stack model. */
 if(x87_count<2u)return;
 if(direction>0){
  double t=x87_stack[0];
  for(uint32_t i=1;i<x87_count;i++)x87_stack[i-1u]=x87_stack[i];
  x87_stack[x87_count-1u]=t;
 }else{
  double t=x87_stack[x87_count-1u];
  for(uint32_t i=x87_count-1u;i>0u;i--)x87_stack[i]=x87_stack[i-1u];
  x87_stack[0]=t;
 }
}
static float x87_load_f32(uint32_t p){union{uint32_t u;float f;}x;x.u=rd32(p);return x.f;}
static double x87_load_f64(uint32_t p){union{uint64_t u;double d;}x;x.u=(uint64_t)rd32(p)|((uint64_t)rd32(p+4u)<<32);return x.d;}
static int32_t x87_load_i32(uint32_t p){return (int32_t)rd32(p);}
static int16_t x87_load_i16(uint32_t p){return (int16_t)rd16(p);}
static int64_t x87_load_i64(uint32_t p){
 uint64_t u=(uint64_t)rd32(p)|((uint64_t)rd32(p+4u)<<32);return (int64_t)u;
}
static void x87_store_f32(uint32_t p,double v){union{uint32_t u;float f;}x;x.f=(float)v;wr32(p,x.u);}
static void x87_store_f64(uint32_t p,double v){union{uint64_t u;double d;}x;x.d=v;wr32(p,(uint32_t)x.u);wr32(p+4u,(uint32_t)(x.u>>32));}
static void x87_store_i16(uint32_t p,int16_t v){wr16(p,(uint16_t)v);}
static void x87_store_i32(uint32_t p,int32_t v){wr32(p,(uint32_t)v);}
static void x87_store_i64(uint32_t p,int64_t v){uint64_t u=(uint64_t)v;wr32(p,(uint32_t)u);wr32(p+4u,(uint32_t)(u>>32));}

static double x87_abs(double x){return x<0.0?-x:x;}
static double x87_floor0(double x){int64_t i=(int64_t)x;return (double)i-(x<0.0&&(double)i!=x?1.0:0.0);}
static double x87_ceil0(double x){int64_t i=(int64_t)x;return (double)i+(x>0.0&&(double)i!=x?1.0:0.0);}
static double x87_round(double x,int truncate){
 if(truncate)return (double)(int64_t)x;
 uint32_t rc=(x87_control>>10)&3u;
 if(rc==1u)return x87_floor0(x);
 if(rc==2u)return x87_ceil0(x);
 if(rc==3u)return (double)(int64_t)x;
 double a=x87_abs(x);int64_t i=(int64_t)a;double f=a-(double)i;
 if(f>0.5 || (f==0.5 && (i&1)))i++;
 return x<0.0?-(double)i:(double)i;
}
static double x87_sqrt(double x){
 if(x<0.0)return 0.0/0.0;if(x==0.0)return x;if(x87_is_inf(x))return x;
 double g=x>1.0?x:1.0;
 for(int i=0;i<24;i++)g=0.5*(g+x/g);
 return g;
}
static double x87_wrap_pi(double x){
 const double PI=3.14159265358979323846,TWO=6.28318530717958647692;
 if(x>1.0e6||x<-1.0e6){
  int64_t k=(int64_t)(x/TWO);x-=((double)k)*TWO;
 }
 while(x>3.14159265358979323846)x-=TWO;
 while(x<-3.14159265358979323846)x+=TWO;
 return x;
}
static double x87_sin(double x){
 const double PI=3.14159265358979323846,HALF=1.57079632679489661923,TWO=6.28318530717958647692;
 x=x87_wrap_pi(x);
 if(x>HALF)x=PI-x;
 else if(x<-HALF)x=-PI-x;
 double x2=x*x;
 return x*(1.0-x2*(1.0/6.0-x2*(1.0/120.0-x2*(1.0/5040.0-x2/362880.0))));
}
static double x87_cos(double x){return x87_sin(x+1.57079632679489661923);}
static double x87_atan(double x){
 int neg=x<0.0;if(neg)x=-x;
 if(x>1.0){double r=1.57079632679489661923-x87_atan(1.0/x);return neg?-r:r;}
 double x2=x*x;
 double r=x*(1.0-x2*(1.0/3.0-x2*(1.0/5.0-x2*(1.0/7.0-x2/9.0))));
 return neg?-r:r;
}
static double x87_log2(double x){
 if(x<=0.0)return -1.0/0.0;
 int e=0;
 while(x>=2.0){x*=0.5;e++;}
 while(x<1.0){x*=2.0;e--;}
 double y=(x-1.0)/(x+1.0),y2=y*y,sum=0.0,p=y;
 for(int n=1;n<=19;n+=2){sum+=p/(double)n;p*=y2;}
 return (double)e+(2.0*sum/0.69314718055994530942);
}
static double x87_exp2(double x){
 int32_t n=(int32_t)x;
 if((double)n>x)n--;
 double f=x-(double)n;
 double ln2=0.69314718055994530942;
 double p=1.0,t=1.0;
 for(int i=1;i<=12;i++){t*=f*ln2/(double)i;p+=t;}
 double scale=1.0;
 if(n>0)for(int i=0;i<n;i++)scale*=2.0;
 else for(int i=0;i>-n;i++)scale*=0.5;
 return scale*p;
}
static int x87_modrm_ea(uint8_t m,uint32_t *ip,uint32_t *ea){if((m>>6)==3)return 0;return modrm_ea(m,ip,ea);}

static uint16_t x87_status_word(void){
 return (uint16_t)(x87_status | ((uint16_t)(x87_count?0:0)<<11));
}
static void x87_init_state(void){
 x87_count=0;x87_status=0;x87_control=0x037Fu;
 x87_trace_reset();
 for(uint32_t i=0;i<8u;i++)x87_stack[i]=0.0;
}
/* FCOMI/FUCOMI family: compare ST0 with ST(i) and report through EFLAGS (ZF,PF,CF); OF/SF/AF cleared. */
static void x87_set_eflags_compare(double a,double b){
 uint32_t f=eflags&~(CF|PF|AF|ZF|SF|OF);
 if(x87_is_nan(a)||x87_is_nan(b))f|=ZF|PF|CF;
 else if(a==b)f|=ZF;
 else if(a<b)f|=CF;
 eflags=f;
}
static int cpu_step_x87(uint8_t op,uint32_t *ip){
 uint32_t x87_eip=*ip-1u;
 uint8_t m=MEM8((*ip)++),mod=(m>>6)&3u,sub=(m>>3)&7u,r=m&7u;uint32_t ea=0;
 x87_trace_begin(x87_eip,op,m);
 if(mod!=3u&&!x87_modrm_ea(m,ip,&ea))return -60;

 /* D8/DC: floating memory/register arithmetic and compare. */
 if(op==0xD8u||op==0xDCu){
  if(mod==3u){
   if(!x87_need_top()||!x87_valid_reg(r))return -61;
   double a=x87_stack[0],b=x87_stack[r];
   if(sub==2u||sub==3u){
    x87_set_compare(a,b);if(sub==3u&&!x87_pop())return -61;return 0;
   }
   if(op==0xD8u){
    if(sub==0u)x87_stack[0]=a+b;
    else if(sub==1u)x87_stack[0]=a*b;
    else if(sub==4u)x87_stack[0]=a-b;
    else if(sub==5u)x87_stack[0]=b-a;
    else if(sub==6u)x87_stack[0]=a/b;
    else if(sub==7u)x87_stack[0]=b/a;
    else {cpu_error=0xD800u|sub;return -60;}
   }else{
    if(sub==0u)x87_stack[r]=b+a;
    else if(sub==1u)x87_stack[r]=b*a;
    else if(sub==4u)x87_stack[r]=b-a;
    else if(sub==5u)x87_stack[r]=a-b;
    else if(sub==6u)x87_stack[r]=b/a;
    else if(sub==7u)x87_stack[r]=a/b;
    else {cpu_error=0xDC00u|sub;return -60;}
   }
   return 0;
  }
  if(!x87_need_top())return -61;
  double v=(op==0xD8u)?(double)x87_load_f32(ea):x87_load_f64(ea);
  if(sub==0u)x87_stack[0]+=v;
  else if(sub==1u)x87_stack[0]*=v;
  else if(sub==2u)x87_set_compare(x87_stack[0],v);
  else if(sub==3u){x87_set_compare(x87_stack[0],v);if(!x87_pop())return -61;}
  else if(sub==4u)x87_stack[0]-=v;
  else if(sub==5u)x87_stack[0]=v-x87_stack[0];
  else if(sub==6u)x87_stack[0]/=v;
  else if(sub==7u)x87_stack[0]=v/x87_stack[0];
  else {cpu_error=0xD800u|sub;return -60;}
  return 0;
 }

 /* D9: single precision loads/stores and the common register-only x87 core. */
 if(op==0xD9u){
  if(mod!=3u){
   if(sub==0u)return x87_push((double)x87_load_f32(ea))?0:-62;
   if(sub==2u||sub==3u){if(!x87_need_top())return -61;x87_store_f32(ea,x87_stack[0]);if(sub==3u&&!x87_pop())return -61;return 0;}
   if(sub==5u){x87_control=rd16(ea);return 0;} /* FLDCW */
   if(sub==7u){wr16(ea,x87_control);return 0;} /* FNSTCW */
   cpu_error=0xD900u|sub;return -60;
  }
  if((m&0xF8u)==0xC0u){if(!x87_valid_reg(r))return -61;double v=x87_stack[r];return x87_push(v)?0:-62;} /* FLD ST(i) */
  if((m&0xF8u)==0xC8u)return x87_fxch(r)?0:-61;
  switch(m){
   case 0xD0: return 0; /* FNOP */
   case 0xE0: if(!x87_need_top())return -61;x87_stack[0]=-x87_stack[0];return 0;
   case 0xE1: if(!x87_need_top())return -61;x87_stack[0]=x87_abs(x87_stack[0]);return 0;
   case 0xE4: if(!x87_need_top())return -61;x87_set_compare(x87_stack[0],0.0);return 0;
   case 0xE5: if(!x87_need_top())return -61;return 0; /* FXAM */
   case 0xE8: return x87_push(1.0)?0:-62;
   case 0xE9: return x87_push(3.32192809488736234787)?0:-62;
   case 0xEA: return x87_push(1.44269504088896340736)?0:-62;
   case 0xEB: return x87_push(3.14159265358979323846)?0:-62;
   case 0xEC: return x87_push(0.30102999566398119521)?0:-62;
   case 0xED: return x87_push(0.69314718055994530942)?0:-62;
   case 0xEE: return x87_push(0.0)?0:-62;
   case 0xF0: if(!x87_need_top())return -61;x87_stack[0]=x87_exp2(x87_stack[0])-1.0;return 0; /* F2XM1 */
   case 0xF1: if(!x87_valid_reg(1)||!x87_need_top())return -61;x87_stack[1]*=x87_log2(x87_stack[0]);return x87_pop()?0:-61; /* FYL2X */
   case 0xF2: if(!x87_need_top())return -61;{double t=x87_sin(x87_stack[0])/x87_cos(x87_stack[0]);x87_stack[0]=t;return x87_push(1.0)?0:-62;} /* FPTAN */
   case 0xF3: if(!x87_valid_reg(1)||!x87_need_top())return -61;x87_stack[1]=x87_atan(x87_stack[1]/x87_stack[0]);return x87_pop()?0:-61; /* FPATAN */
   case 0xF4: if(!x87_need_top())return -61;{double v=x87_stack[0],av=x87_abs(v);int e=0;while(av>=2.0){av*=0.5;e++;}while(av>0.0&&av<1.0){av*=2.0;e--;}double sig=v;double scale=1.0;if(e>0)for(int i=0;i<e;i++)scale*=2.0;else for(int i=0;i>-e;i++)scale*=0.5;if(scale!=0.0)sig=v/scale;x87_stack[0]=(double)e;return x87_push(sig)?0:-62;} /* FXTRACT */
   case 0xF5: if(!x87_valid_reg(1)||!x87_need_top())return -61;{double q=x87_stack[0]/x87_stack[1];int64_t n=(int64_t)q;x87_stack[0]-=x87_stack[1]*(double)n;x87_status&=~(X87_C0|X87_C1|X87_C2|X87_C3);x87_status|=(uint16_t)((n&4)?X87_C0:0)|((n&1)?X87_C1:0)|((n&2)?X87_C3:0);return 0;} /* FPREM1-compatible */
   case 0xF6: x87_rotate_top(-1);return 0; /* FDECSTP */
   case 0xF7: x87_rotate_top(+1);return 0; /* FINCSTP */
   case 0xF8: if(!x87_valid_reg(1)||!x87_need_top())return -61;{double q=x87_stack[0]/x87_stack[1];int64_t n=(int64_t)q;x87_stack[0]-=x87_stack[1]*(double)n;x87_status&=~(X87_C0|X87_C1|X87_C2|X87_C3);x87_status|=(uint16_t)((n&4)?X87_C0:0)|((n&1)?X87_C1:0)|((n&2)?X87_C3:0);return 0;} /* FPREM */
   case 0xF9: if(!x87_valid_reg(1)||!x87_need_top())return -61;x87_stack[0]=x87_stack[1]*x87_log2(1.0+x87_stack[0]);return x87_pop()?0:-61; /* FYL2XP1 */
   case 0xFA: if(!x87_need_top())return -61;x87_stack[0]=x87_sqrt(x87_stack[0]);return 0; /* FSQRT */
   case 0xFB: if(!x87_need_top())return -61;{double v=x87_stack[0],c=x87_cos(v),sn=x87_sin(v);x87_stack[0]=sn;return x87_push(c)?0:-62;} /* FSINCOS */
   case 0xFC: if(!x87_need_top())return -61;x87_stack[0]=x87_round(x87_stack[0],0);return 0; /* FRNDINT */
   case 0xFD: if(!x87_valid_reg(1)||!x87_need_top())return -61;x87_stack[0]*=x87_exp2(x87_round(x87_stack[1],1));return 0; /* FSCALE */
   case 0xFE: if(!x87_need_top())return -61;x87_stack[0]=x87_sin(x87_stack[0]);return 0; /* FSIN */
   case 0xFF: if(!x87_need_top())return -61;x87_stack[0]=x87_cos(x87_stack[0]);return 0; /* FCOS */
   default: break;
  }
  if((m&0xF8u)==0xD0u){if(!x87_need_top()||!x87_valid_reg(r))return -61;x87_stack[r]=x87_stack[0];return 0;}
  if((m&0xF8u)==0xD8u){if(!x87_need_top()||!x87_valid_reg(r))return -61;x87_stack[r]=x87_stack[0];return x87_pop()?0:-61;}
 }

 /* DB: 32-bit integer load/store plus FCMOVcc. */
 if(op==0xDBu){
  if(mod!=3u){
   if(sub==0u)return x87_push((double)x87_load_i32(ea))?0:-62;
   if(sub==1u){if(!x87_need_top()){return -61;}x87_store_i32(ea,(int32_t)x87_round(x87_stack[0],1));return x87_pop()?0:-61;}
   if(sub==2u||sub==3u){if(!x87_need_top())return -61;x87_store_i32(ea,(int32_t)x87_round(x87_stack[0],0));if(sub==3u&&!x87_pop())return -61;return 0;}
   cpu_error=0xDB00u|sub;return -60;
  }
  /* DB C0..DF: FCMOVNB/NE/NBE/NU ST0,STi. */
  if((m&0xF8u)>=0xC0u&&(m&0xF8u)<=0xD8u){
   uint32_t block=(m>>3)&3u;
   int take=(block==0)?!(eflags&CF):(block==1)?!(eflags&ZF):(block==2)?(!(eflags&CF)&&!(eflags&ZF)):!(eflags&PF);
   if(take){if(!x87_valid_reg(r)||!x87_need_top())return -61;x87_stack[0]=x87_stack[r];}
   return 0;
  }
  if(m==0xE0u||m==0xE1u||m==0xE4u)return 0;               /* FENI/FDISI/FSETPM: 8087-era no-ops */
  if(m==0xE2u){x87_status&=(uint16_t)~0x80FFu;return 0;}  /* FNCLEX */
  if(m==0xE3u){x87_init_state();return 0;}                /* FNINIT */
  if((m&0xF0u)==0xE8u||(m&0xF0u)==0xF0u){                 /* FUCOMI (E8+i) / FCOMI (F0+i) */
   if(!x87_need_top()||!x87_valid_reg(r))return -61;
   x87_set_eflags_compare(x87_stack[0],x87_stack[r]);return 0;
  }
 }

 /* DA: integer arithmetic and FCMOVB/E/BE/U. */
 if(op==0xDAu){
  if(mod!=3u){
   if(sub>7u){cpu_error=0xDA00u|sub;return -60;}
   if(!x87_need_top())return -61;
   int32_t iv=x87_load_i32(ea);double v=(double)iv;
   if(sub==0u)x87_stack[0]+=v;else if(sub==1u)x87_stack[0]*=v;else if(sub==2u)x87_set_compare(x87_stack[0],v);else if(sub==3u){x87_set_compare(x87_stack[0],v);if(!x87_pop())return -61;}else if(sub==4u)x87_stack[0]-=v;else if(sub==5u)x87_stack[0]=v-x87_stack[0];else if(sub==6u)x87_stack[0]/=v;else x87_stack[0]=v/x87_stack[0];return 0;
  }
  if(m==0xE9u){                                            /* FUCOMPP */
   if(!x87_valid_reg(1)||!x87_need_top())return -61;
   x87_set_compare(x87_stack[0],x87_stack[1]);
   if(!x87_pop())return -61;if(!x87_pop())return -61;return 0;
  }
  if((m&0xF8u)>=0xC0u&&(m&0xF8u)<=0xD8u){
   uint32_t block=(m>>3)&3u;
   int take=(block==0)?(eflags&CF):(block==1)?(eflags&ZF):(block==2)?((eflags&CF)||(eflags&ZF)):(eflags&PF);
   if(take){if(!x87_valid_reg(r)||!x87_need_top())return -61;x87_stack[0]=x87_stack[r];}
   return 0;
  }
 }

 /* DD: double-precision loads/stores and stack-pop arithmetic. */
 if(op==0xDDu){
  if(mod!=3u){
   /* DD memory operands are 64-bit. Validate the entire operand before
    * reading/writing it so failed accesses do not mutate x87 state. */
   uint32_t access=(sub==0u)?X86_MEM_READ:X86_MEM_WRITE;
   if(!x86_mem_region_find(ea,8u,access)){
    x86_mem_faults++;
    x86_last_fault_address=ea;
    x86_last_fault_size=8u;
    x86_last_fault_kind=access;
    cpu_error=0xE100u|((access==X86_MEM_READ)?1u:2u);
    return -62;
   }
   if(sub==0u)return x87_push((double)x87_load_i64(ea))?0:-62; /* FILD m64int */
   if(sub==1u){if(!x87_need_top())return -61;x87_store_i64(ea,(int64_t)x87_round(x87_stack[0],1));return x87_pop()?0:-61;}
   if(sub==2u||sub==3u){if(!x87_need_top())return -61;x87_store_f64(ea,x87_stack[0]);if(sub==3u&&!x87_pop())return -61;return 0;}
   if(sub==7u){wr16(ea,x87_status_word());return 0;} /* FNSTSW */
   cpu_error=0xDD00u|sub;return -60;
  }
  if((m&0xF0u)==0xE0u){                                   /* FUCOM (E0+i) / FUCOMP (E8+i) */
   if(!x87_need_top()||!x87_valid_reg(r))return -61;
   x87_set_compare(x87_stack[0],x87_stack[r]);
   if((m&0x08u)&&!x87_pop())return -61;return 0;
  }
  if((m&0xF8u)==0xC0u){if(!x87_valid_reg(r))return -61;x87_stack[r]=0.0;return 0;} /* FFREE */
  if((m&0xF8u)==0xD0u){if(!x87_valid_reg(r)||!x87_need_top())return -61;x87_stack[r]=x87_stack[0];return 0;}
  if((m&0xF8u)==0xD8u){if(!x87_valid_reg(r)||!x87_need_top())return -61;x87_stack[r]=x87_stack[0];return x87_pop()?0:-61;}
 }

 /* DE: 16-bit integer arithmetic and the P forms that consume ST0. */
 if(op==0xDEu&&mod==3u){
  if(m==0xD9u){if(!x87_valid_reg(1)){cpu_error=0xD802u;return -61;}x87_set_compare(x87_stack[0],x87_stack[1]);if(!x87_pop())return -61;if(!x87_pop())return -61;return 0;}
  if(!x87_need_top()||!x87_valid_reg(r))return -61;
  double a=x87_stack[0],b=x87_stack[r];
  if(sub==0u)x87_stack[r]=b+a;else if(sub==1u)x87_stack[r]=b*a;else if(sub==4u)x87_stack[r]=b-a;else if(sub==5u)x87_stack[r]=a-b;else if(sub==6u)x87_stack[r]=b/a;else if(sub==7u)x87_stack[r]=a/b;else{cpu_error=0xDE00u|sub;return -60;}
  return x87_pop()?0:-61;
 }
 if(op==0xDEu&&mod!=3u){
  if(!x87_need_top())return -61;
  int16_t iv=x87_load_i16(ea);double v=(double)iv;
  if(sub==0u)x87_stack[0]+=v;else if(sub==1u)x87_stack[0]*=v;else if(sub==2u)x87_set_compare(x87_stack[0],v);else if(sub==3u){x87_set_compare(x87_stack[0],v);if(!x87_pop())return -61;}else if(sub==4u)x87_stack[0]-=v;else if(sub==5u)x87_stack[0]=v-x87_stack[0];else if(sub==6u)x87_stack[0]/=v;else if(sub==7u)x87_stack[0]=v/x87_stack[0];return 0;
 }

 /* DF: 16/64-bit integer load/store and FNSTSW AX. */
 if(op==0xDFu){
  if(mod==3u&&m==0xE0u){reg16_write(0,x87_status_word());return 0;}
  if(mod==3u&&((m&0xF0u)==0xE8u||(m&0xF0u)==0xF0u)){       /* FUCOMIP (E8+i) / FCOMIP (F0+i) */
   if(!x87_need_top()||!x87_valid_reg(r))return -61;
   x87_set_eflags_compare(x87_stack[0],x87_stack[r]);
   return x87_pop()?0:-61;
  }
  if(mod!=3u){
   if(sub==0u)return x87_push((double)x87_load_i16(ea))?0:-62;
   if(sub==1u){if(!x87_need_top())return -61;x87_store_i16(ea,(int16_t)x87_round(x87_stack[0],1));return x87_pop()?0:-61;}
   if(sub==2u||sub==3u){if(!x87_need_top())return -61;x87_store_i16(ea,(int16_t)x87_round(x87_stack[0],0));if(sub==3u&&!x87_pop())return -61;return 0;}
   if(sub==5u)return x87_push((double)x87_load_i64(ea))?0:-62;
   if(sub==7u){if(!x87_need_top())return -61;x87_store_i64(ea,(int64_t)x87_round(x87_stack[0],0));return x87_pop()?0:-61;}
  }
 }

 cpu_error=0xD800u|op;return -60;
}

static int cpu_step_legacy(void){
 uint32_t ip=eip,eip_before_site=eip; uint8_t op=MEM8(ip++); steps++;
 switch(op){
  case 0xFC:eflags&=~DF;eip=ip;return 0;
  case 0xFD:eflags|=DF;eip=ip;return 0;
  case 0xA4:case 0xA5:case 0xA6:case 0xA7:case 0xAA:case 0xAB:case 0xAC:case 0xAD:case 0xAE:case 0xAF:string_execute(op);eip=ip;return 0;
  case 0x88:{uint8_t m=MEM8(ip++),v=reg8_read((m>>3)&7);modrm_write8(m,&ip,v);eip=ip;return 0;}
  case 0x8A:{uint8_t m=MEM8(ip++);reg8_write((m>>3)&7,modrm_read8(m,&ip));eip=ip;return 0;}
  case 0x87: { /* XCHG r/m32,r32 */
   uint8_t m=MEM8(ip++);
   uint32_t other=regs[(m>>3)&7u];
   if((m>>6)==3){
    uint32_t t=regs[m&7u]; regs[m&7u]=other; regs[(m>>3)&7u]=t;
   }else{
    uint32_t ea=0;
    if(!modrm_ea(m,&ip,&ea)){cpu_error=0x8700u;return -55;}
    uint32_t t=rd32(ea); wr32(ea,other); regs[(m>>3)&7u]=t;
   }
   eip=ip;return 0;
  }
  case 0x90: eip=ip; return 0; /* NOP / XCHG EAX,EAX */
  case 0x91:case 0x92:case 0x93:case 0x94:case 0x95:case 0x96:case 0x97: {
   uint32_t r=op-0x90u,t=regs[R_EAX];regs[R_EAX]=regs[r];regs[r]=t;eip=ip;return 0;
  }
  case 0xF4: eip=ip; halted=1; return 1; /* HLT */
  case 0x31: { /* XOR r/m32,r32 (register and memory forms) */
   uint8_t m=MEM8(ip++);
   uint32_t src=regs[(m>>3)&7];
   if((m>>6)==3){uint32_t *dst=&regs[m&7];*dst^=src;set_logic_flags(*dst);eip=ip;return 0;}
   uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=2;return -2;}
   uint32_t r=rd32(ea)^src;wr32(ea,r);set_logic_flags(r);eip=ip;return 0;
  }
  case 0x33: { /* XOR r32,r/m32 (register and memory forms) */
   uint8_t m=MEM8(ip++);
   uint32_t src;
   if((m>>6)==3)src=regs[m&7];else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=3;return -3;}src=rd32(ea);}
   uint32_t *dst=&regs[(m>>3)&7];*dst^=src;set_logic_flags(*dst);eip=ip;return 0;
  }
  case 0xB8:case 0xB9:case 0xBA:case 0xBB:case 0xBC:case 0xBD:case 0xBE:case 0xBF:
   regs[op-0xB8]=rd32(ip); eip=ip+4; return 0; /* MOV r32,imm32 */
  case 0x8B: { /* MOV r32/r16,r/m */
   uint8_t m=MEM8(ip++); if(decoded_operand16){reg16_write((m>>3)&7,modrm_read16(m,&ip));}else{regs[(m>>3)&7]=modrm_read32(m,&ip);} eip=ip; return 0;
  }
  case 0x89: { /* MOV r/m32/r16,r32/r16 */
   uint8_t m=MEM8(ip++); if(decoded_operand16)modrm_write16(m,&ip,reg16_read((m>>3)&7));else modrm_write32(m,&ip,regs[(m>>3)&7]); eip=ip; return 0;
  }
  case 0x8D: { /* LEA r32,m */
   uint8_t m=MEM8(ip++); uint32_t ea=0; if(!modrm_ea(m,&ip,&ea)){cpu_error=0x8D;return -11;} regs[(m>>3)&7]=ea; eip=ip; return 0;
  }
  case 0x00:case 0x02:case 0x08:case 0x0A:case 0x10:case 0x12:case 0x18:case 0x1A:case 0x20:case 0x22:case 0x28:case 0x2A:case 0x30:case 0x32:case 0x38:case 0x3A:case 0x84:{
   uint8_t m=MEM8(ip++),d=(m>>3)&7;uint8_t a,b,r;uint32_t ea=0;
   if((m>>6)==3)a=reg8_read(m&7);else{modrm_ea(m,&ip,&ea);a=MEM8(ea);}
   b=reg8_read(d);
   switch(op&0xF8u){case 0x00:r=(uint8_t)(a+b);set_add_flags_width(a,b,r,8);break;case 0x08:r=(uint8_t)(a|b);set_logic_flags_width(r,8);break;case 0x10:{uint32_t c=(eflags&CF)?1u:0u;r=(uint8_t)(a+b+c);set_adc_flags_width(a,b,c,r,8);break;}case 0x18:{uint32_t c=(eflags&CF)?1u:0u;r=(uint8_t)(a-b-c);set_sbb_flags_width(a,b,c,r,8);break;}case 0x20:r=(uint8_t)(a&b);set_logic_flags_width(r,8);break;case 0x28:r=(uint8_t)(a-b);set_sub_flags_width(a,b,r,8);break;case 0x30:r=(uint8_t)(a^b);set_logic_flags_width(r,8);break;default:if(op==0x84)set_logic_flags_width((uint8_t)(a&b),8);else set_sub_flags_width(a,b,(uint8_t)(a-b),8);eip=ip;return 0;}
   if(op==0x02||op==0x0A||op==0x12||op==0x1A||op==0x22||op==0x2A||op==0x32||op==0x3A)reg8_write(d,r);else if(op==0x84){set_logic_flags_width((uint8_t)(a&b),8);eip=ip;return 0;}else if((m>>6)==3)reg8_write(m&7,r);else wr8(ea,r);
   eip=ip;return 0;
  }
  case 0x04:case 0x0C:case 0x14:case 0x1C:case 0x24:case 0x2C:case 0x34:case 0x3C:{
   uint8_t b=MEM8(ip++),a=reg8_read(0),r;switch(op){case 0x04:r=a+b;set_add_flags_width(a,b,r,8);break;case 0x0C:r=a|b;set_logic_flags_width(r,8);break;case 0x14:{uint32_t c=(eflags&CF)?1u:0u;r=a+b+c;set_adc_flags_width(a,b,c,r,8);break;}case 0x1C:{uint32_t c=(eflags&CF)?1u:0u;r=a-b-c;set_sbb_flags_width(a,b,c,r,8);break;}case 0x24:r=a&b;set_logic_flags_width(r,8);break;case 0x2C:r=a-b;set_sub_flags_width(a,b,r,8);break;case 0x34:r=a^b;set_logic_flags_width(r,8);break;default:set_sub_flags_width(a,b,(uint8_t)(a-b),8);eip=ip;return 0;}reg8_write(0,r);eip=ip;return 0;
  }
  case 0x80:{
   uint8_t m=MEM8(ip++),sub=(m>>3)&7;uint32_t ea=0;uint8_t a=(m>>6)==3?reg8_read(m&7):(modrm_ea(m,&ip,&ea),MEM8(ea)),b=MEM8(ip++),r;
   if(sub==0){r=a+b;set_add_flags_width(a,b,r,8);}else if(sub==2){uint32_t c=(eflags&CF)?1u:0u;r=a+b+c;set_adc_flags(a,b,c,r);}else if(sub==3){uint32_t c=(eflags&CF)?1u:0u;r=a-b-c;set_sbb_flags(a,b,c,r);}else if(sub==4){r=a&b;set_logic_flags_width(r,8);}else if(sub==5){r=a-b;set_sub_flags_width(a,b,r,8);}else if(sub==6){r=a^b;set_logic_flags_width(r,8);}else if(sub==7){set_sub_flags_width(a,b,(uint8_t)(a-b),8);eip=ip;return 0;}else{cpu_error=0x8000u|sub;return -40;}if(sub!=7){if((m>>6)==3)reg8_write(m&7,r);else wr8(ea,r);}eip=ip;return 0;
  }
  case 0x01: { /* ADD r/m32,r32 */
   uint8_t m=MEM8(ip++); uint32_t ea=0,b=regs[(m>>3)&7]; uint32_t a;
   if((m>>6)==3)a=regs[m&7]; else {modrm_ea(m,&ip,&ea);a=rd32(ea);}
   uint32_t r=a+b; set_add_flags(a,b,r);
   if((m>>6)==3)regs[m&7]=r; else wr32(ea,r);
   eip=ip; return 0;
  }
  case 0x29: { /* SUB r/m32,r32 */
   uint8_t m=MEM8(ip++); uint32_t ea=0,b=regs[(m>>3)&7]; uint32_t a;
   if((m>>6)==3)a=regs[m&7]; else {modrm_ea(m,&ip,&ea);a=rd32(ea);}
   uint32_t r=a-b; set_sub_flags(a,b,r);
   if((m>>6)==3)regs[m&7]=r; else wr32(ea,r);
   eip=ip; return 0;
  }
  case 0x09: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t ea=0,v=regs[d]; if((m>>6)==3){v|=regs[m&7];regs[m&7]=v;}else{modrm_ea(m,&ip,&ea);v=rd32(ea)|v;wr32(ea,v);} set_logic_flags(v);eip=ip;return 0; } /* OR r/m32,r32 */
  case 0x0D: { uint32_t b=rd32(ip),v=regs[R_EAX]|b; regs[R_EAX]=v; set_logic_flags(v); eip=ip+4; return 0; } /* OR EAX,imm32 */
  case 0x0B: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t v=regs[d]|modrm_read32(m,&ip);regs[d]=v;set_logic_flags(v);eip=ip;return 0; } /* OR r32,r/m32 */
  case 0x21: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t ea=0,v=regs[d]; if((m>>6)==3){v&=regs[m&7];regs[m&7]=v;}else{modrm_ea(m,&ip,&ea);v=rd32(ea)&v;wr32(ea,v);}set_logic_flags(v);eip=ip;return 0; } /* AND r/m32,r32 */
  case 0x23: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t v=regs[d]&modrm_read32(m,&ip);regs[d]=v;set_logic_flags(v);eip=ip;return 0; } /* AND r32,r/m32 */
  case 0x25: { uint32_t b=rd32(ip); ip+=4; uint32_t v=regs[R_EAX]&b; regs[R_EAX]=v; set_logic_flags(v); eip=ip; return 0; } /* AND EAX,imm32 */
  case 0x2B: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t a=regs[d],b=modrm_read32(m,&ip),v=a-b;set_sub_flags(a,b,v);regs[d]=v;eip=ip;return 0; } /* SUB r32,r/m32 */
  case 0x03: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t a=regs[d],b=modrm_read32(m,&ip),v=a+b;set_add_flags(a,b,v);regs[d]=v;eip=ip;return 0; } /* ADD r32,r/m32 */
  case 0x3B: { uint8_t m=MEM8(ip++),d=(m>>3)&7; uint32_t a=regs[d],b=modrm_read32(m,&ip);set_sub_flags(a,b,a-b);eip=ip;return 0; } /* CMP r32,r/m32 */
  case 0x81: { uint8_t m=MEM8(ip++),sub=(m>>3)&7; uint32_t ea=0,a; if((m>>6)==3)a=regs[m&7];else{modrm_ea(m,&ip,&ea);a=rd32(ea);} uint32_t b=rd32(ip);ip+=4; uint32_t v;
   if(sub==0){v=a+b;set_add_flags(a,b,v);}else if(sub==2){uint32_t c=(eflags&CF)?1u:0u;v=a+b+c;set_adc_flags(a,b,c,v);}else if(sub==3){uint32_t c=(eflags&CF)?1u:0u;v=a-b-c;set_sbb_flags(a,b,c,v);}else if(sub==5){v=a-b;set_sub_flags(a,b,v);}else if(sub==6){v=a^b;set_logic_flags(v);}else if(sub==7){set_sub_flags(a,b,a-b);eip=ip;return 0;}else{cpu_error=0x8100u|sub;return -13;}
   if((m>>6)==3)regs[m&7]=v;else wr32(ea,v);eip=ip;return 0; } /* ADD/SUB/CMP r/m32,imm32 */
  case 0x83: { uint8_t m=MEM8(ip++),sub=(m>>3)&7; uint32_t ea=0,a; if((m>>6)==3)a=regs[m&7];else{modrm_ea(m,&ip,&ea);a=rd32(ea);} int32_t sb=(int8_t)MEM8(ip++);uint32_t b=(uint32_t)sb,v;
   if(sub==0){v=a+b;set_add_flags(a,b,v);}else if(sub==1){v=a|b;set_logic_flags(v);}else if(sub==2){uint32_t c=(eflags&CF)?1u:0u;v=a+b+c;set_adc_flags(a,b,c,v);}else if(sub==3){uint32_t c=(eflags&CF)?1u:0u;v=a-b-c;set_sbb_flags(a,b,c,v);}else if(sub==4){v=a&b;set_logic_flags(v);}else if(sub==5){v=a-b;set_sub_flags(a,b,v);}else if(sub==7){set_sub_flags(a,b,a-b);eip=ip;return 0;}else{cpu_error=0x8300u|sub;return -14;}
   if((m>>6)==3)regs[m&7]=v;else wr32(ea,v);eip=ip;return 0; } /* ADD/SUB/CMP r/m32,imm8 */
  case 0x39: { /* CMP r/m32,r32 */
   uint8_t m=MEM8(ip++); uint32_t ea=0,b=regs[(m>>3)&7],a;
   if((m>>6)==3)a=regs[m&7]; else {modrm_ea(m,&ip,&ea);a=rd32(ea);}
   uint32_t r=a-b; set_sub_flags(a,b,r); eip=ip; return 0;
  }
  case 0x85: { /* TEST r/m32,r32 */
   uint8_t m=MEM8(ip++); uint32_t v=modrm_read32(m,&ip)&regs[(m>>3)&7]; set_logic_flags(v); eip=ip; return 0;
  }
  case 0x11: {uint8_t m=MEM8(ip++);uint32_t ea=0,a,b=regs[(m>>3)&7],cin=(eflags&CF)?1u:0u;if((m>>6)==3)a=regs[m&7];else{modrm_ea(m,&ip,&ea);a=rd32(ea);}uint32_t r=a+b+cin;set_adc_flags(a,b,cin,r);if((m>>6)==3)regs[m&7]=r;else wr32(ea,r);eip=ip;return 0;}
  case 0x13: {uint8_t m=MEM8(ip++),d=(m>>3)&7,cin=(eflags&CF)?1u:0u,a=regs[d],b=modrm_read32(m,&ip),r=a+b+cin;set_adc_flags(a,b,cin,r);regs[d]=r;eip=ip;return 0;}
  case 0x15: {uint32_t b=rd32(ip),cin=(eflags&CF)?1u:0u,a=regs[R_EAX],r=a+b+cin;set_adc_flags(a,b,cin,r);regs[R_EAX]=r;eip=ip+4;return 0;}
  case 0x19: {uint8_t m=MEM8(ip++);uint32_t ea=0,a,b=regs[(m>>3)&7],bin=(eflags&CF)?1u:0u;if((m>>6)==3)a=regs[m&7];else{modrm_ea(m,&ip,&ea);a=rd32(ea);}uint32_t r=a-b-bin;set_sbb_flags(a,b,bin,r);if((m>>6)==3)regs[m&7]=r;else wr32(ea,r);eip=ip;return 0;}
  case 0x1B: {uint8_t m=MEM8(ip++),d=(m>>3)&7,bin=(eflags&CF)?1u:0u,a=regs[d],b=modrm_read32(m,&ip),r=a-b-bin;set_sbb_flags(a,b,bin,r);regs[d]=r;eip=ip;return 0;}
  case 0x1D: {uint32_t b=rd32(ip),bin=(eflags&CF)?1u:0u,a=regs[R_EAX],r=a-b-bin;set_sbb_flags(a,b,bin,r);regs[R_EAX]=r;eip=ip+4;return 0;}
  case 0x05: {uint32_t b=rd32(ip);uint32_t r=regs[R_EAX]+b;set_add_flags(regs[R_EAX],b,r);regs[R_EAX]=r;eip=ip+4;return 0;}
  case 0x2D: {uint32_t b=rd32(ip);uint32_t r=regs[R_EAX]-b;set_sub_flags(regs[R_EAX],b,r);regs[R_EAX]=r;eip=ip+4;return 0;}
  case 0x3D: {uint32_t b=rd32(ip);uint32_t r=regs[R_EAX]-b;set_sub_flags(regs[R_EAX],b,r);eip=ip+4;return 0;} /* CMP EAX,imm32 */
  case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
   /* Group 2: 8/16/32-bit shifts and rotates. */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7;
   uint32_t bits=(op==0xC0||op==0xD0||op==0xD2)?8u:(decoded_operand16?16u:32u);
   uint32_t mask=bits==8?0xFFu:(bits==16?0xFFFFu:0xFFFFFFFFu);
   uint32_t sign=1u<<(bits-1u);
   uint32_t ea=0,v;
   if((m>>6)==3) v=bits==8?reg8_read(m&7):bits==16?reg16_read(m&7):regs[m&7];
   else {modrm_ea(m,&ip,&ea);v=bits==8?MEM8(ea):bits==16?rd16(ea):rd32(ea);}
   v&=mask;
   uint32_t count=(op==0xC0||op==0xC1)?MEM8(ip++):((op==0xD2||op==0xD3)?(regs[R_ECX]&31u):1u);
   uint32_t cf=(eflags&CF)?1u:0u,of=0,of_valid=0,r=v;
   if(sub>=4){
    count&=31u;if(!count){eip=ip;return 0;}
    if(sub==4){r=(v<<count)&mask;cf=(v>>(bits-count))&1u;of_valid=count==1;of=((r&sign)?1u:0u)^cf;}
    else if(sub==5){r=v>>count;cf=(v>>(count-1u))&1u;of_valid=count==1;of=(v&sign)?1u:0u;}
    else if(sub==7){r=(uint32_t)(((int32_t)(v|((v&sign)?~mask:0u)))>>count)&mask;cf=(v>>(count-1u))&1u;of_valid=0;}
    else {cpu_error=0xC000u|sub;return -35;}
    set_shift_flags(r,cf,of_valid,of);
   }else{
    uint32_t modulus=bits==8?9u:(bits==16?17u:33u);
    count&=31u;count%=modulus;if(!count){eip=ip;return 0;}
    uint64_t x=((uint64_t)cf<<bits)|v;
    uint64_t fullmask=(1ull<<(bits+1u))-1ull;
    if(sub==0){
     r=(uint32_t)(((uint64_t)v<<count)|(v>>(bits-count)))&mask;
     cf=r&1u;of_valid=count==1;of=((r&sign)?1u:0u)^cf;
    }else if(sub==1){
     r=(v>>count)|(v<<(bits-count));r&=mask;
     cf=(r&sign)?1u:0u;of_valid=count==1;of=((r&sign)?1u:0u)^((r>>(bits-2u))&1u);
    }else if(sub==2){
     x=((x<<count)|(x>>(bits+1u-count)))&fullmask;r=(uint32_t)x&mask;cf=(uint32_t)((x>>bits)&1u);
     of_valid=count==1;of=((r&sign)?1u:0u)^cf;
    }else{
     x=((x>>count)|(x<<(bits+1u-count)))&fullmask;r=(uint32_t)x&mask;cf=(uint32_t)((x>>bits)&1u);
     of_valid=count==1;of=((r&sign)?1u:0u)^((r>>(bits-2u))&1u);
    }
    set_rotate_flags(r,cf,of_valid,of);
   }
   if((m>>6)==3){
    if(bits==8)reg8_write(m&7,(uint8_t)r);
    else if(bits==16)reg16_write(m&7,(uint16_t)r);
    else regs[m&7]=r;
   }else{
    if(bits==8)wr8(ea,(uint8_t)r);
    else if(bits==16)modrm_write16(m,&(uint32_t){ip},(uint16_t)r);
    else wr32(ea,r);
   }
   eip=ip;return 0;
  }
  case 0x69: {uint8_t m=MEM8(ip++);uint32_t a=modrm_read32(m,&ip),imm=rd32(ip);ip+=4;int64_t p=(int64_t)(int32_t)a*(int64_t)(int32_t)imm;uint32_t r=(uint32_t)p;uint32_t sx=(uint32_t)(int32_t)r;eflags=(eflags&~(CF|OF))|((p!=(int64_t)(int32_t)r)?(CF|OF):0);regs[(m>>3)&7]=r;eip=ip;return 0;}
  case 0x6B: {uint8_t m=MEM8(ip++);uint32_t a=modrm_read32(m,&ip);int32_t imm=(int8_t)MEM8(ip++);int64_t p=(int64_t)(int32_t)a*(int64_t)imm;uint32_t r=(uint32_t)p;eflags=(eflags&~(CF|OF))|((p!=(int64_t)(int32_t)r)?(CF|OF):0);regs[(m>>3)&7]=r;eip=ip;return 0;}
  case 0xF6: { /* TEST/NOT/NEG r/m8 (MUL/DIV r/m8 are not implemented) */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7u;uint32_t ea=0;uint8_t v;
   if(sub>3u){cpu_error=0xF600u|sub;return -47;}
   if((m>>6)==3)v=reg8_read(m&7u);else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0xF601u;return -48;}v=MEM8(ea);}
   if(sub<2u){uint8_t imm=MEM8(ip++);set_logic_flags_width((uint32_t)(v&imm),8u);}
   else{
    uint8_t r=(sub==2u)?(uint8_t)~v:(uint8_t)(0u-v);
    if(sub==3u){set_sub_flags_width(0u,v,r,8u);eflags=(eflags&~CF)|(v?CF:0u);}
    if((m>>6)==3)reg8_write(m&7u,r);else wr8(ea,r);
   }
   eip=ip;return 0;
  }
  case 0xF7: { /* NOT/NEG/MUL/IMUL/DIV/IDIV r/m32 */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7; uint32_t ea=0,v=(m>>6)==3?regs[m&7]:(modrm_ea(m,&ip,&ea),rd32(ea));
   if(sub==2){v=~v;if((m>>6)==3)regs[m&7]=v;else wr32(ea,v);eip=ip;return 0;}
   if(sub==3){uint32_t r=0u-v;set_sub_flags(0u,v,r);if(v)eflags|=CF;else eflags&=~CF;if(v==0x80000000u)eflags|=OF;else eflags&=~OF;if((m>>6)==3)regs[m&7]=r;else wr32(ea,r);eip=ip;return 0;}
   if(sub==4){uint64_t p=(uint64_t)regs[R_EAX]*(uint64_t)v;regs[R_EAX]=(uint32_t)p;regs[R_EDX]=(uint32_t)(p>>32);eflags=(eflags&~(CF|OF))|(((p>>32)!=0)?(CF|OF):0);eip=ip;return 0;}
   if(sub==5){int64_t p=(int64_t)(int32_t)regs[R_EAX]*(int64_t)(int32_t)v;uint32_t lo=(uint32_t)p,hi=(uint32_t)((uint64_t)p>>32);regs[R_EAX]=lo;regs[R_EDX]=hi;int64_t sx=(int64_t)(int32_t)lo;eflags=(eflags&~(CF|OF))|((p!=sx)?(CF|OF):0);eip=ip;return 0;}
   if(sub==6){if(v==0){cpu_error=0xF706u;return -30;}uint64_t dividend=((uint64_t)regs[R_EDX]<<32)|regs[R_EAX];uint64_t q=dividend/v,r=dividend%v;if(q>0xFFFFFFFFull){cpu_error=0xF707u;return -31;}regs[R_EAX]=(uint32_t)q;regs[R_EDX]=(uint32_t)r;eip=ip;return 0;}
   if(sub==7){if(v==0){cpu_error=0xF708u;return -32;}int32_t divisor=(int32_t)v;int64_t dividend=((int64_t)(int32_t)regs[R_EDX]<<32)|(uint32_t)regs[R_EAX];if(dividend==(-9223372036854775807ll-1ll)&&divisor==-1){cpu_error=0xF709u;return -33;}int64_t q=dividend/divisor,r=dividend%divisor;if(q>2147483647ll||q<(-2147483647ll-1ll)){cpu_error=0xF709u;return -33;}regs[R_EAX]=(uint32_t)q;regs[R_EDX]=(uint32_t)r;eip=ip;return 0;}
   cpu_error=0xF700u|sub;return -34;
  }
  case 0x40:case 0x41:case 0x42:case 0x43:case 0x44:case 0x45:case 0x46:case 0x47:
   {uint32_t r=regs[op-0x40]+1;regs[op-0x40]=r; /* INC does not modify CF */
    uint32_t old=eflags;set_add_flags(regs[op-0x40]-1,1,r);eflags=(eflags&~CF)|(old&CF);eip=ip;return 0;}
  case 0x48:case 0x49:case 0x4A:case 0x4B:case 0x4C:case 0x4D:case 0x4E:case 0x4F:
   {uint32_t r=regs[op-0x48]-1;uint32_t old=eflags;set_sub_flags(regs[op-0x48]+1,1,r);eflags=(eflags&~CF)|(old&CF);regs[op-0x48]=r;eip=ip;return 0;}
  case 0xE9:{int32_t d=(int32_t)rd32(ip);eip=ip+4+(uint32_t)d;return 0;} /* JMP rel32 */
  case 0xEB:{int8_t d=(int8_t)MEM8(ip);eip=ip+1+(int32_t)d;return 0;} /* JMP rel8 */
  case 0x70:case 0x71:case 0x72:case 0x73:case 0x74:case 0x75:case 0x76:case 0x77:case 0x78:case 0x79:case 0x7A:case 0x7B:case 0x7C:case 0x7D:case 0x7E:case 0x7F:{
   int8_t d=(int8_t)MEM8(ip++);eip=cond(op)?ip+(int32_t)d:ip;return 0;
  }
  case 0x60: { /* PUSHAD */
   uint32_t original_esp=regs[R_ESP];
   if(!x86_stack_push32(regs[R_EAX]))return -51;
   if(!x86_stack_push32(regs[R_ECX]))return -51;
   if(!x86_stack_push32(regs[R_EDX]))return -51;
   if(!x86_stack_push32(regs[R_EBX]))return -51;
   if(!x86_stack_push32(original_esp))return -51;
   if(!x86_stack_push32(regs[R_EBP]))return -51;
   if(!x86_stack_push32(regs[R_ESI]))return -51;
   if(!x86_stack_push32(regs[R_EDI]))return -51;
   eip=ip;return 0;
  }
  case 0x61: { /* POPAD */
   uint32_t discarded;
   if(!x86_stack_pop32(&regs[R_EDI]))return -52;
   if(!x86_stack_pop32(&regs[R_ESI]))return -52;
   if(!x86_stack_pop32(&regs[R_EBP]))return -52;
   if(!x86_stack_pop32(&discarded))return -52; /* original ESP */
   if(!x86_stack_pop32(&regs[R_EBX]))return -52;
   if(!x86_stack_pop32(&regs[R_EDX]))return -52;
   if(!x86_stack_pop32(&regs[R_ECX]))return -52;
   if(!x86_stack_pop32(&regs[R_EAX]))return -52;
   eip=ip;return 0;
  }
  case 0x98: { /* CWDE: sign-extend AX into EAX */
   regs[R_EAX]=(uint32_t)(int32_t)(int16_t)(regs[R_EAX]&0xFFFFu);
   eip=ip;return 0;
  }
  case 0x99: { /* CDQ: sign-extend EAX into EDX:EAX */
   regs[R_EDX]=(regs[R_EAX]&0x80000000u)?0xFFFFFFFFu:0u;
   eip=ip;return 0;
  }
  case 0x9C: { /* PUSHFD */
   if(!x86_stack_push32(eflags|0x00000002u))return -53;
   eip=ip;return 0;
  }
  case 0x9D: { /* POPFD */
   uint32_t v;
   if(!x86_stack_pop32(&v))return -54;
   eflags=(v&0x00000FD5u)|0x00000002u;
   eip=ip;return 0;
  }
  case 0xA8:{uint8_t b=MEM8(ip++),a=reg8_read(0);set_logic_flags_width((uint8_t)(a&b),8);eip=ip;return 0;} /* TEST AL,imm8 */
  case 0xA9:{uint32_t b=rd32(ip),a=regs[R_EAX];set_logic_flags(a&b);eip=ip+4;return 0;} /* TEST EAX,imm32 */
  case 0x68:{uint32_t v=rd32(ip);ip+=4;if(!x86_stack_push32(v))return -42;eip=ip;return 0;} /* PUSH imm32 */
  case 0x6A:{int8_t v=(int8_t)MEM8(ip++);if(!x86_stack_push32((uint32_t)(int32_t)v))return -43;eip=ip;return 0;} /* PUSH imm8 */
  case 0x8F:{ /* POP r/m32 */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7u; uint32_t v,ea=0;
   if(sub!=0u){cpu_error=0x8F00u|sub;return -57;}
   if(!x86_stack_pop32(&v))return -55;
   if((m>>6)==3)regs[m&7u]=v;
   else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0x8F01u;return -58;}wr32(ea,v);}
   eip=ip;return 0;
  }
  case 0x58:case 0x59:case 0x5A:case 0x5B:case 0x5C:case 0x5D:case 0x5E:case 0x5F:{
   uint32_t v;
   if(!x86_stack_pop32(&v))return -55;
   regs[op-0x58]=v;eip=ip;return 0;
  }
  case 0x50:case 0x51:case 0x52:case 0x53:case 0x54:case 0x55:case 0x56:case 0x57:
   if(!x86_stack_push32(regs[op-0x50]))return -56;
   eip=ip;return 0;
  case 0xFE:{ /* INC/DEC r/m8 */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7u;uint32_t ea=0;uint8_t a,r;uint32_t old_cf=eflags&CF;
   if(sub>1u){cpu_error=0xFE00u|sub;return -59;}
   if((m>>6)==3)a=reg8_read(m&7u);else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0xFE01u;return -60;}a=MEM8(ea);}
   if(sub==0u){r=(uint8_t)(a+1u);set_add_flags_width(a,1u,r,8);}else{r=(uint8_t)(a-1u);set_sub_flags_width(a,1u,r,8);}
   eflags=(eflags&~CF)|old_cf;
   if((m>>6)==3)reg8_write(m&7u,r);else wr8(ea,r);
   eip=ip;return 0;
  }
  case 0xCC:{ /* INT3: browser-compatible soft breakpoint/no-op */ eip=ip; return 0; }
  case 0x0F: {
   uint8_t op2=MEM8(ip++);
   if(op2==0x10u||op2==0x11u){ /* MOVUPS xmm,xmm/m128 and MOVUPS xmm/m128,xmm */
    uint8_t m=MEM8(ip++),d=(m>>3)&7u,s=m&7u;uint32_t ea=0;
    if((m>>6)==3u){
     if(op2==0x10u){
      for(uint32_t b=0;b<16u;b++)xmm[d][b]=xmm[s][b];
     }else{
      for(uint32_t b=0;b<16u;b++)xmm[s][b]=xmm[d][b];
     }
    }else{
     if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F10u|op2;return -18;}
     if(!x86_mem_region_find(ea,16u,op2==0x10u?X86_MEM_READ:X86_MEM_WRITE)){
      x86_mem_faults++;x86_last_fault_address=ea;x86_last_fault_size=16u;
      x86_last_fault_kind=op2==0x10u?X86_MEM_READ:X86_MEM_WRITE;
      cpu_error=0xE100u|(op2==0x10u?1u:2u);return -62;
     }
     if(op2==0x10u){
      for(uint32_t b=0;b<16u;b++)xmm[d][b]=MEM8(ea+b);
     }else{
      for(uint32_t b=0;b<16u;b++)wr8(ea+b,xmm[d][b]);
     }
    }
    eip=ip;return 0;
   }
   if(op2==0xAF){uint8_t m=MEM8(ip++);int64_t p=(int64_t)(int32_t)regs[(m>>3)&7]*(int64_t)(int32_t)modrm_read32(m,&ip);uint32_t r=(uint32_t)p;regs[(m>>3)&7]=r;eflags=(eflags&~(CF|OF))|((p!=(int64_t)(int32_t)r)?(CF|OF):0);eip=ip;return 0;}
   if(op2==0x1Fu||op2==0x18u){uint8_t m=MEM8(ip++);uint32_t ea=0;if((m>>6)!=3)modrm_ea(m,&ip,&ea);eip=ip;return 0;} /* multi-byte NOP / PREFETCH */
   if(op2>=0x40u&&op2<=0x4Fu){ /* CMOVcc r,r/m */
    uint8_t m=MEM8(ip++);int take;
    if(decoded_operand16){uint16_t v=modrm_read16(m,&ip);take=cond((uint8_t)(0x70u+(op2&0xFu)));if(take)reg16_write((m>>3)&7u,v);}
    else{uint32_t v=modrm_read32(m,&ip);take=cond((uint8_t)(0x70u+(op2&0xFu)));if(take)regs[(m>>3)&7]=v;}
    eip=ip;return 0;
   }
   if(op2>=0x90u&&op2<=0x9Fu){ /* SETcc r/m8 */
    uint8_t m=MEM8(ip++),v=cond((uint8_t)(0x70u+(op2&0xFu)))?1u:0u;
    if((m>>6)==3)reg8_write(m&7u,v);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F00u|op2;return -19;}wr8(ea,v);}
    eip=ip;return 0;
   }
   if(op2==0xBF){uint8_t m=MEM8(ip++);uint16_t v;if((m>>6)==3)v=reg16_read(m&7u);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0FBFu;return -17;}v=rd16(ea);}regs[(m>>3)&7]=(uint32_t)(int32_t)(int16_t)v;eip=ip;return 0;} /* MOVSX r32,r/m16 */
   if(op2==0xBC||op2==0xBD){ /* BSF/BSR */
    uint8_t m=MEM8(ip++);uint32_t v=modrm_read32(m,&ip);
    if(v==0){eflags|=ZF;}
    else{uint32_t i=0;if(op2==0xBC){while(!((v>>i)&1u))i++;}else{i=31;while(!((v>>i)&1u))i--;}regs[(m>>3)&7]=i;eflags&=~ZF;}
    eip=ip;return 0;
   }
   if(op2>=0xC8u&&op2<=0xCFu){uint32_t v=regs[op2-0xC8u];regs[op2-0xC8u]=(v>>24)|((v>>8)&0xFF00u)|((v<<8)&0xFF0000u)|(v<<24);eip=ip;return 0;} /* BSWAP */
   if(op2==0xC1){ /* XADD r/m32,r32 */
    uint8_t m=MEM8(ip++);uint32_t ea=0,d,s0=regs[(m>>3)&7];
    if((m>>6)==3)d=regs[m&7];else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0FC1u;return -19;}d=rd32(ea);}
    uint32_t r=d+s0;set_add_flags_width(d,s0,r,32u);
    regs[(m>>3)&7]=d;if((m>>6)==3)regs[m&7]=r;else wr32(ea,r);
    eip=ip;return 0;
   }
   if(op2==0xA4||op2==0xA5||op2==0xAC||op2==0xAD){ /* SHLD/SHRD r/m32,r32,imm8|CL */
    uint8_t m=MEM8(ip++);uint32_t ea=0,d,s0=regs[(m>>3)&7];
    if((m>>6)==3)d=regs[m&7];else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F00u|op2;return -19;}d=rd32(ea);}
    uint8_t c=(uint8_t)(((op2==0xA4)||(op2==0xAC))?MEM8(ip++):(uint8_t)regs[R_ECX]);c&=31u;
    if(c){
     uint32_t r,cf;
     if(op2==0xA4||op2==0xA5){r=(d<<c)|(s0>>(32u-c));cf=(d>>(32u-c))&1u;}
     else{r=(d>>c)|(s0<<(32u-c));cf=(d>>(c-1u))&1u;}
     set_logic_flags_width(r,32u);
     eflags=(eflags&~(CF|OF))|(cf?CF:0u)|((c==1u&&(((d^r)>>31)&1u))?OF:0u);
     if((m>>6)==3)regs[m&7]=r;else wr32(ea,r);
    }
    eip=ip;return 0;
   }
   if(op2==0x44){uint8_t m=MEM8(ip++);uint32_t v=modrm_read32(m,&ip);if(eflags&ZF)regs[(m>>3)&7]=v;eip=ip;return 0;}
   if(op2==0x90||op2==0x92){uint8_t m=MEM8(ip++);uint8_t v=(op2==0x90)?((eflags&OF)?1u:0u):((eflags&CF)?1u:0u);if((m>>6)==3)reg8_write(m&7u,v);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F00u|op2;return -19;}wr8(ea,v);}eip=ip;return 0;}
   if(op2==0x94){uint8_t m=MEM8(ip++),v=(eflags&ZF)?1u:0u;if((m>>6)==3)reg8_write(m&7u,(uint8_t)v);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F94u;return -19;}wr8(ea,(uint8_t)v);}eip=ip;return 0;}
   if(op2==0x95){uint8_t m=MEM8(ip++),v=(eflags&ZF)?0u:1u;if((m>>6)==3)reg8_write(m&7u,(uint8_t)v);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F95u;return -19;}wr8(ea,(uint8_t)v);}eip=ip;return 0;}
   if(op2==0xB7){uint8_t m=MEM8(ip++);uint16_t v;if((m>>6)==3)v=reg16_read(m&7u);else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0FB7u;return -17;}v=rd16(ea);}if(decoded_operand16)reg16_write((m>>3)&7u,v);else regs[(m>>3)&7u]=(uint32_t)v;eip=ip;return 0;}
   if(op2==0xB6||op2==0xBE){uint8_t m=MEM8(ip++);uint32_t v;if((m>>6)==3){v=regs[m&7]&0xFFu;}else{uint32_t ea=0;if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0F00u|op2;return -17;}v=MEM8(ea);}if(op2==0xBE&&v&0x80u)v|=0xFFFFFF00u;regs[(m>>3)&7]=v;eip=ip;return 0;}
   if(op2==0xAE){uint8_t m=MEM8(ip++),sub=(m>>3)&7u;uint32_t ea=0;if(sub!=1u||(m>>6)==3){cpu_error=0x0FAEu|sub;return -18;}if(!modrm_ea(m,&ip,&ea)){cpu_error=0x0FAE01u;return -18;}if(!x86_mem_region_find(ea,512u,X86_MEM_READ)){x86_mem_faults++;cpu_error=0xE100u|1u;return -62;}x87_control=rd16(ea);x87_status=rd16(ea+2u);eip=ip;return 0;}
   if(op2==0xA3||op2==0xAB||op2==0xB3||op2==0xBB){uint8_t m=MEM8(ip++),d=(m>>3)&7;int32_t bit=(int32_t)regs[d];uint32_t ea=0,shift=(uint32_t)bit&31u,v;if((m>>6)==3)v=regs[m&7];else{modrm_ea(m,&ip,&ea);ea+=(uint32_t)(bit>>5)*4u;v=rd32(ea);}uint32_t old=(v>>shift)&1u;eflags=(eflags&~CF)|(old?CF:0);if(op2!=0xA3){if(op2==0xAB)v|=1u<<shift;else if(op2==0xB3)v&=~(1u<<shift);else v^=1u<<shift;if((m>>6)==3)regs[m&7]=v;else wr32(ea,v);}eip=ip;return 0;}
   if(op2==0xBA){uint8_t m=MEM8(ip++),sub=(m>>3)&7,bit=MEM8(ip++);if(sub<4||sub>7){cpu_error=0x0FBAu|sub;return -36;}uint32_t ea=0,v,shift=bit&31u;if((m>>6)==3)v=regs[m&7];else{modrm_ea(m,&ip,&ea);v=rd32(ea);}uint32_t old=(v>>shift)&1u;eflags=(eflags&~CF)|(old?CF:0);if(sub!=4){if(sub==5)v|=1u<<shift;else if(sub==6)v&=~(1u<<shift);else v^=1u<<shift;if((m>>6)==3)regs[m&7]=v;else wr32(ea,v);}eip=ip;return 0;}
   if(op2>=0x80&&op2<=0x8F){int32_t d=(int32_t)rd32(ip);ip+=4;uint8_t shortop=(uint8_t)(0x70u+(op2-0x80u));eip=cond(shortop)?ip+(uint32_t)d:ip;return 0;}
   cpu_error=0x0F00u|op2;return -18;
  }
  case 0xE3:{int8_t d=(int8_t)MEM8(ip++);eip=(regs[R_ECX]==0)?ip+(int32_t)d:ip;return 0;} /* JECXZ */
  case 0xE0:case 0xE1:case 0xE2:{int8_t d=(int8_t)MEM8(ip++);regs[R_ECX]--;uint32_t take=(regs[R_ECX]!=0);if(op==0xE1)take=take&&((eflags&ZF)!=0);if(op==0xE0)take=take&&((eflags&ZF)==0);eip=take?ip+(int32_t)d:ip;return 0;}
  case 0xC6:{ /* MOV r/m8,imm8 */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7u;
   if(sub!=0u){cpu_error=0xC600u|sub;return -47;}
   uint32_t ea=0;uint8_t v=MEM8(ip++);
   if((m>>6)==3)reg8_write(m&7u,v);
   else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0xC601u;return -48;}wr8(ea,v);}
   eip=ip;return 0;
  }
  case 0xC7:{ /* MOV r/m32,imm32 */
   uint8_t m=MEM8(ip++),sub=(m>>3)&7u;
   if(sub!=0u){cpu_error=0xC700u|sub;return -49;}
   uint32_t ea=0,v;
   if((m>>6)==3){v=rd32(ip);ip+=4;regs[m&7u]=v;}
   else{if(!modrm_ea(m,&ip,&ea)){cpu_error=0xC701u;return -50;}v=rd32(ip);ip+=4;wr32(ea,v);}
   eip=ip;return 0;
  }
  case 0xC9:{uint32_t v;regs[R_ESP]=regs[R_EBP];if(!x86_stack_pop32(&v))return -44;regs[R_EBP]=v;eip=ip;return 0;} /* LEAVE */
  case 0xC2:{uint16_t n=rd16(ip);ip+=2;uint32_t v,esp0=regs[R_ESP];if(!x86_stack_pop32(&v))return -45;x86_shadow_ret(eip,v,esp0);if(!x86_stack_discard(n))return -46;eip=v;return 0;} /* RET imm16 */
  case 0xFF: { /* Group 5: INC/DEC/CALL/JMP/PUSH r/m32 subset. */
   uint8_t m=MEM8(ip++);
   uint8_t sub=(m>>3)&7;
   uint32_t ea=0,target;
   if(sub==6){ /* PUSH r/m32 -- required by FS/GS-prefixed compiler prologues. */
    uint32_t value=modrm_ea(m,&ip,&ea)?rd32(ea):regs[m&7u];
    if(!x86_stack_push32(value))return -57;
    eip=ip;
    return 0;
   }
   if(sub==0u||sub==1u){ /* INC/DEC r/m32 (or r/m16 with operand-size override). */
    uint32_t is_mem=(uint32_t)modrm_ea(m,&ip,&ea);
    uint32_t width=decoded_operand16?16u:32u;
    uint32_t mask=decoded_operand16?0xFFFFu:0xFFFFFFFFu;
    uint32_t a=is_mem?(decoded_operand16?(uint32_t)rd16(ea):rd32(ea)):
      (decoded_operand16?(uint32_t)reg16_read(m&7u):regs[m&7u]);
    uint32_t old_cf=eflags&CF;
    uint32_t r=sub==0u?(a+1u)&mask:(a-1u)&mask;
    if(sub==0u)set_add_flags_width(a,1u,r,width);
    else set_sub_flags_width(a,1u,r,width);
    eflags=(eflags&~CF)|old_cf; /* INC/DEC preserve CF. */
    if(is_mem){
     if(decoded_operand16){wr8(ea,(uint8_t)r);wr8(ea+1u,(uint8_t)(r>>8));}
     else wr32(ea,r);
    }else if(decoded_operand16)reg16_write(m&7u,(uint16_t)r);
    else regs[m&7u]=r;
    eip=ip;return 0;
   }
   if(sub!=2&&sub!=4){cpu_error=0xFF00u|sub;return -12;}
   if(modrm_ea(m,&ip,&ea))target=rd32(ea);else{ea=0;target=regs[m&7u];}
   uint32_t next=ip;
   last_indirect_slot=ea;last_indirect_target=target;
   if(!target){
    x86_control_fault_kind=1u;x86_control_fault_eip=eip;x86_control_fault_next_eip=next;
    x86_control_fault_target=0u;x86_control_fault_slot=ea;x86_control_fault_opcode=0xFFu;x86_control_fault_modrm=m;
    cpu_error=0xFF10u;return -58;
   } /* indirect call/jmp through a null pointer (unpatched IAT slot) */
   if(target>=API_UNRESOLVED_BASE&&target<API_UNRESOLVED_END){
    /* Unresolved import: stop with a precise diagnosis instead of executing hint/name bytes. */
    last_unresolved_gdr=(target==API_UNRESOLVED_ORDINAL)?0xFFFFFFFEu:((target-API_UNRESOLVED_BASE)>>2);
    x86_control_fault_kind=2u;x86_control_fault_eip=eip;x86_control_fault_next_eip=next;
    x86_control_fault_target=target;x86_control_fault_slot=ea;x86_control_fault_opcode=0xFFu;x86_control_fault_modrm=m;
    x86_gdr_note_call(ea);
    cpu_error=0xFF20u;return -63;
   }
   /*
    * A PE import thunk is normally an FF /4 or FF /2 through an IAT slot.
    * If that slot was overwritten by guest code, do not jump to the foreign
    * value. Re-resolve the slot from its immutable GDR metadata instead.
    * This is especially important for the browser runtime because an invalid
    * host-looking pointer here would otherwise become a guest EIP and turn a
    * simple IAT corruption into an opaque 0xD001/0xE101 failure.
    */
   if(target<image_base || target>=image_base+image_size){
    int rebound=x86_gdr_rebind_slot(ea);
    if(rebound>0)target=rd32(ea);
    else if(rebound<0){
     target=rd32(ea);
     last_unresolved_gdr=(target>=API_UNRESOLVED_BASE&&target<API_UNRESOLVED_END)?
       ((target-API_UNRESOLVED_BASE)>>2):0xFFFFFFFFu;
     x86_control_fault_kind=2u;x86_control_fault_eip=eip;x86_control_fault_next_eip=next;
     x86_control_fault_target=target;x86_control_fault_slot=ea;x86_control_fault_opcode=0xFFu;x86_control_fault_modrm=m;
     x86_gdr_note_call(ea);
     cpu_error=0xFF20u;return -63;
    }else{
     x86_control_fault_kind=3u;x86_control_fault_eip=eip;x86_control_fault_next_eip=next;
     x86_control_fault_target=target;x86_control_fault_slot=ea;x86_control_fault_opcode=0xFFu;x86_control_fault_modrm=m;
    }
   }
   if(sub==2){
    x86_gdr_note_call(ea);
    if(!x86_stack_push32(next))return -57;
    if(call_builtin(target)){eip=next;regs[R_ESP]+=4u;return 0;}
    eip=target;x86_shadow_call(eip_before_site,next,target);return 0;
   }
   /* FF /4 JMP is frequently used by PE import thunks. Record the import
    * call and, if resolved to a host/API shim, execute it before returning
    * through the thunk's existing caller return address. */
   x86_gdr_note_call(ea);
   /* A JMP thunk runs with the caller's return address on top of the stack. Host shims and xapi
    * handlers remove stdcall arguments from ESP before returning, so the return address has to be
    * read BEFORE the handler runs; reading it afterwards picked up the last argument instead. */
   uint32_t thunk_ret=0,thunk_sp=regs[R_ESP];
   if(!x86_mem_region_find(thunk_sp,4u,X86_MEM_READ))thunk_sp=0;else thunk_ret=rd32(thunk_sp);
   if(call_builtin(target)){
    if(!thunk_sp){x86_mem_faults++;cpu_error=0xE002u;return -57;}
    x86_shadow_ret(eip,thunk_ret,thunk_sp);
    regs[R_ESP]+=4u;
    eip=thunk_ret;
    return 0;
   }
   eip=target;return 0;
  }
  case 0xC3:{uint32_t v,esp0=regs[R_ESP];if(!x86_stack_pop32(&v))return -49;x86_shadow_ret(eip,v,esp0);eip=v;return 0;} /* RET */
  case 0xE8:{int32_t d=(int32_t)rd32(ip);uint32_t next=ip+4;if(!x86_stack_push32(next))return -50;eip=next+(uint32_t)d;x86_shadow_call(eip_before_site,next,eip);return 0;} /* CALL rel32 */
  default: cpu_error=op; return -10;
 }
}

#include "cpu_decoder.c"

static int image_rva_valid(uint32_t rva,uint32_t size){
 return rva<=image_size && size<=image_size-rva;
}
static uint32_t x86_gdr_add(uint32_t dll_rva,uint32_t func_rva,uint32_t iat_rva,uint32_t target,uint32_t status){
 if(x86_gdr_count>=X86_GDR_MAX_IMPORTS)return 0xFFFFFFFFu;
 uint32_t i=x86_gdr_count++;
 x86_gdr[i].dll_rva=dll_rva;
 x86_gdr[i].func_rva=func_rva;
 x86_gdr[i].iat_rva=iat_rva;
 x86_gdr[i].target=target;
 x86_gdr[i].status=status;
 x86_gdr[i].call_count=0;
 return i;
}
static void x86_gdr_note_call(uint32_t slot){
 if(slot<image_base)return;
 uint32_t rva=slot-image_base;
 for(uint32_t i=0;i<x86_gdr_count;i++)
  if(x86_gdr[i].iat_rva==rva){
   x86_gdr[i].call_count++;
   return;
  }
}
static void x86_gdr_reset(void){
 x86_gdr_count=0;
 for(uint32_t i=0;i<X86_GDR_MAX_IMPORTS;i++)x86_gdr[i]=(x86_gdr_record_t){0};
}
static void scan_imports(void){
 dll_count=0; import_count=0; import_resolved=0; import_failed=0; last_import_dll=0; last_import_func=0; last_import_thunk=0; last_import_target=0; last_failed_import_dll=0; last_failed_import_func=0;
 x86_gdr_reset();
 if(!import_rva||!import_size||!image_rva_valid(import_rva,20))return;
 uint32_t p=image_base+import_rva;
 uint32_t max=image_base+import_rva+import_size;
 for(uint32_t n=0;p+20u<=max;n++,p+=20u){
  uint32_t oft=rd32(p),name_rva=rd32(p+12),ft=rd32(p+16);
  if(!oft&&!name_rva&&!ft)break;
  dll_count++;
  if(!name_rva||name_rva>=image_size||!ft||ft>=image_size){import_failed++;continue;}
  uint32_t thunk_rva=oft?oft:ft;
  if(thunk_rva>=image_size){import_failed++;continue;}
  uint32_t thunk=image_base+thunk_rva;
  uint32_t iat=image_base+ft;
  uint32_t dll=image_base+name_rva;
  uint32_t resolved_this_dll=0;
  for(uint32_t i=0;i<0x100000u;i++){
   uint32_t v=rd32(thunk+i*4u);
   if(!v)break;
   if(v&0x80000000u){import_failed++;wr32(iat+i*4u,API_UNRESOLVED_ORDINAL);continue;} /* ordinal imports: trap on call */
   if(v+2u>=image_size){import_failed++;break;}
   uint32_t name=image_base+v+2u;
   import_count++;
   uint32_t gdr_index=x86_gdr_add(name_rva,v,ft+i*4u,0u,X86_GDR_UNRESOLVED);
   uint32_t target=resolve_builtin(dll,name);
   if(target){
    wr32(iat+i*4u,target);
    if(gdr_index!=0xFFFFFFFFu){
     x86_gdr[gdr_index].target=target;
     x86_gdr[gdr_index].status=X86_GDR_RESOLVED;
    }
    import_resolved++;
    last_import_dll=name_rva;
    last_import_func=v;
    last_import_thunk=ft+i*4u;
    last_import_target=target;
    resolved_this_dll++;
   }else{
    import_failed++;
    if(gdr_index!=0xFFFFFFFFu){x86_gdr[gdr_index].target=API_UNRESOLVED_BASE+gdr_index*4u;wr32(iat+i*4u,API_UNRESOLVED_BASE+gdr_index*4u);}
    last_failed_import_dll=name_rva;
    last_failed_import_func=v;
    uint32_t dl=0,fn=0;
    while(dl<255u&&MEM8(image_base+name_rva+dl))dl++;
    while(fn<255u&&MEM8(image_base+v+2u+fn))fn++;
    z_host_log(2,(int32_t)(image_base+name_rva),(int32_t)dl);
    z_host_log(2,(int32_t)(image_base+v+2u),(int32_t)fn);
   }
  }
  (void)resolved_this_dll;
 }
}

#define X86_DLL_MAX_MODULES 32u
#define X86_DLL_MAX_RESOURCES 64u
#define X86_DLL_BASE 0x05000000u
#define X86_DLL_STRIDE 0x00800000u
typedef struct{uint32_t active,base,size,preferred,entry,reloc_rva,reloc_size,export_rva,export_size,imports_resolved,imports_failed,refcount;char name[96];char requested_name[96];}x86_dll_module_t;
typedef struct{uint32_t active,data,size;char name[96];}x86_dll_resource_t;
static x86_dll_module_t x86_dll_modules[X86_DLL_MAX_MODULES];
static x86_dll_resource_t x86_dll_resources[X86_DLL_MAX_RESOURCES];
static uint32_t x86_dll_last_error=0,x86_dll_last_base=0;
static int x86_dll_cname_equal(const char*a,const char*b){uint32_t i=0;if(!a||!b)return 0;while(a[i]&&b[i]){char x=a[i],y=b[i];if(x>='A'&&x<='Z')x=(char)(x-'A'+'a');if(y>='A'&&y<='Z')y=(char)(y-'A'+'a');if(x!=y)return 0;i++;}return a[i]==0&&b[i]==0;}
static int x86_dll_name_equal(uint32_t p,const char*n){uint32_t i=0;if(!p||!n)return 0;while(n[i]){char a=(char)MEM8(p+i),b=n[i];if(a>='A'&&a<='Z')a=(char)(a-'A'+'a');if(b>='A'&&b<='Z')b=(char)(b-'A'+'a');if(a!=b)return 0;i++;}return MEM8(p+i)==0;}
static uint32_t x86_dll_basename_ptr(uint32_t p){uint32_t last=p;if(!p)return 0;for(uint32_t i=0;i<256u&&MEM8(p+i);i++)if(MEM8(p+i)=='/'||MEM8(p+i)=='\\')last=p+i+1u;return last;}
static int x86_dll_find_loaded(uint32_t p){for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active&&x86_dll_name_equal(p,x86_dll_modules[i].requested_name))return (int)i;return -1;}
static int x86_dll_ascii_module_name(uint32_t p){if(!p)return 0;uint32_t b=x86_dll_basename_ptr(p),i=0;while(i<95u&&MEM8(b+i)){char c=(char)MEM8(b+i);if(c>='A'&&c<='Z')c=(char)(c-'A'+'a');if(c=='.'&&MEM8(b+i+1u)=='e'&&MEM8(b+i+2u)=='x'&&MEM8(b+i+3u)=='e'&&MEM8(b+i+4u)==0)return 1;i++;}return 0;}
static uint32_t x86_dll_module_for_wide_name(uint32_t p){
 if(!p)return image_base;
 char s[128],base[128];uint32_t i=0,b=0;
 for(;i<127u;i++){
  uint16_t w=rd16(p+i*2u);
  if(w==0)break;
  char c=(char)(w<128u?w:'?');
  if(c>='A'&&c<='Z')c=(char)(c-'A'+'a');
  s[i]=c;
  if(c=='/'||c=='\\')b=i+1u;
 }
 s[i]=0;
 if(!s[0])return image_base;
 uint32_t bl=0;for(uint32_t k=b;k<i&&bl<127u;k++,bl++)base[bl]=s[k];base[bl]=0;
 for(uint32_t j=0;j<X86_DLL_MAX_MODULES;j++){
  if(!x86_dll_modules[j].active)continue;
  if(x86_dll_cname_equal(s,x86_dll_modules[j].requested_name)||
     x86_dll_cname_equal(base,x86_dll_modules[j].requested_name))
   return x86_dll_modules[j].base;
 }
 /* CRT startup asks for the process image before it has a conventional
  * module-table entry. Resolve the executable name directly to image_base. */
 for(uint32_t k=0;k+4u<bl;k++)
  if(base[k]=='.'&&base[k+1u]=='e'&&base[k+2u]=='x'&&base[k+3u]=='e'&&base[k+4u]==0)
   return image_base;
 /* Some CRTs pass the image name without an extension. A pointer into the
  * loaded PE is a strong indication that this is one of those startup names. */
 if(p>=image_base&&p<image_base+image_size){
  int has_dot=0,has_path=0;
  for(uint32_t k=0;k<bl;k++){if(base[k]=='.')has_dot=1;if(base[k]=='/'||base[k]=='\\')has_path=1;}
  if(!has_dot||has_path)return image_base;
 }
 /* Common Windows CRT startup aliases are represented by the host bridge;
  * give them a stable nonzero module handle rather than failing startup. */
 if(x86_dll_cname_equal(base,"kernel32.dll")||
    x86_dll_cname_equal(base,"kernelbase.dll")||
    x86_dll_cname_equal(base,"user32.dll")||
    x86_dll_cname_equal(base,"gdi32.dll"))
  return image_base;
 return 0;
}
static int x86_dll_guest_name_equal(uint32_t a,uint32_t b){uint32_t i=0;if(!a||!b)return 0;while(MEM8(a+i)&&MEM8(b+i)){char x=(char)MEM8(a+i),y=(char)MEM8(b+i);if(x>='A'&&x<='Z')x=(char)(x-'A'+'a');if(y>='A'&&y<='Z')y=(char)(y-'A'+'a');if(x!=y)return 0;i++;}return MEM8(a+i)==0&&MEM8(b+i)==0;}
static int x86_dll_apply_relocs(uint32_t base,uint32_t size,uint32_t preferred,uint32_t rva,uint32_t rsz){
 if(base==preferred)return 1;if(!rva||!rsz||rva>size||rsz>size-rva)return 0;
 int32_t delta=(int32_t)(base-preferred);uint32_t p=base+rva,end=p+rsz;
 while(p+8u<=end){uint32_t page=rd32(p),block=rd32(p+4u);if(block<8u||p+block>end)return 0;
  uint32_t count=(block-8u)/2u;for(uint32_t i=0;i<count;i++){uint16_t raw=rd16(p+8u+i*2u),type=raw>>12,off=raw&0xFFFu;if(type==0)continue;if(type!=3u)return 0;uint32_t at=base+page+off;if(at<base||at+4u>base+size)return 0;wr32(at,rd32(at)+(uint32_t)delta);}p+=block;
 }return p==end;
}
static uint32_t x86_dll_get_proc(uint32_t module,uint32_t name){
 for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active&&x86_dll_modules[i].base==module){
  x86_dll_module_t*m=&x86_dll_modules[i];if(!m->export_rva||m->export_rva+40u>m->size)return 0;
  uint32_t ed=m->base+m->export_rva,nn=rd32(ed+24u),names=rd32(ed+32u),ords=rd32(ed+36u),funcs=rd32(ed+28u);
  for(uint32_t n=0;n<nn&&n<65536u;n++){uint32_t np=m->base+rd32(m->base+names+n*4u);if(!x86_dll_guest_name_equal(name,np))continue;uint16_t oi=rd16(m->base+ords+n*2u);uint32_t fr=rd32(m->base+funcs+(uint32_t)oi*4u);if(fr>=m->export_rva&&fr<m->export_rva+m->export_size)return 0;return fr<m->size?m->base+fr:0;}
 }return 0;
}
static uint32_t x86_dll_resolve_import(uint32_t dll,uint32_t name){
 uint32_t t=resolve_builtin(dll,name);if(t)return t;
 for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active&&x86_dll_name_equal(dll,x86_dll_modules[i].name)){t=x86_dll_get_proc(x86_dll_modules[i].base,name);if(t)return t;}
 return 0;
}
static int x86_gdr_rebind_slot(uint32_t slot){
 if(slot<image_base)return 0;
 uint32_t rva=slot-image_base;
 for(uint32_t i=0;i<x86_gdr_count;i++){
  x86_gdr_record_t *g=&x86_gdr[i];
  if(g->iat_rva!=rva)continue;
  uint32_t dll=image_base+g->dll_rva;
  uint32_t name=image_base+g->func_rva+2u;
  uint32_t target=resolve_builtin(dll,name);
  if(!target)target=x86_dll_resolve_import(dll,name);
  if(target){
   wr32(slot,target);
   g->target=target;
   g->status=X86_GDR_RESOLVED;
   return 1;
  }
  uint32_t trap=API_UNRESOLVED_BASE+i*4u;
  wr32(slot,trap);
  g->target=trap;
  g->status=X86_GDR_UNRESOLVED;
  last_unresolved_gdr=i;
  return -1;
 }
 return 0;
}
static void x86_dll_resolve_imports(uint32_t base,uint32_t size,uint32_t rva,uint32_t rsz,uint32_t*ok,uint32_t*bad){
 if(ok)*ok=0;if(bad)*bad=0;if(!rva||!rsz||rva>size||rsz>size-rva)return;
 uint32_t p=base+rva,end=p+rsz;
 for(uint32_t d=0;p+20u<=end&&d<256u;d++,p+=20u){uint32_t oft=rd32(p),nr=rd32(p+12u),ft=rd32(p+16u);if(!oft&&!nr&&!ft)break;if(!nr||nr>=size||!ft||ft>=size){if(bad)(*bad)++;continue;}uint32_t th=base+(oft?oft:ft),iat=base+ft;
  for(uint32_t j=0;j<0x100000u;j++){uint32_t v=rd32(th+j*4u);if(!v)break;if(v&0x80000000u){wr32(iat+j*4u,API_UNRESOLVED_ORDINAL);if(bad)(*bad)++;continue;}if(v+2u>=size){if(bad)(*bad)++;break;}uint32_t t=x86_dll_resolve_import(base+nr,base+v+2u);if(t){wr32(iat+j*4u,t);if(ok)(*ok)++;}else{wr32(iat+j*4u,API_UNRESOLVED_BASE);if(bad)(*bad)++;}}
 }
}
static int x86_dll_load_image(uint32_t f,uint32_t sz,uint32_t requested_name){
 if(sz<0x40u||rd16(f)!=0x5A4Du){x86_dll_last_error=1;return 0;}uint32_t pe=rd32(f+0x3Cu);
 if(pe+24u>sz||rd32(f+pe)!=0x4550u){x86_dll_last_error=2;return 0;}uint16_t mach=rd16(f+pe+4u),nsec=rd16(f+pe+6u),optsz=rd16(f+pe+20u),chars=rd16(f+pe+22u);
 if(mach!=0x14Cu||(chars&0x2000u)==0||optsz<224u){x86_dll_last_error=3;return 0;}uint32_t oh=f+pe+24u;if(oh+optsz>f+sz||rd16(oh)!=0x10Bu){x86_dll_last_error=4;return 0;}
 uint32_t isz=rd32(oh+56u),hsz=rd32(oh+60u),entry=rd32(oh+16u),pref=rd32(oh+28u),dirs=rd32(oh+92u),er=0,es=0,ir=0,is=0,rr=0,rs=0;
 if(isz<0x1000u||isz>0x02000000u||hsz>sz||hsz>isz){x86_dll_last_error=5;return 0;}if(dirs>0u){er=rd32(oh+96u);es=rd32(oh+100u);}
 if(dirs>1u){ir=rd32(oh+104u);is=rd32(oh+108u);}if(dirs>5u){rr=rd32(oh+136u);rs=rd32(oh+140u);}
 uint32_t sh=oh+optsz;if(sh+(uint32_t)nsec*40u>f+sz){x86_dll_last_error=6;return 0;}
 int slot=-1;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(!x86_dll_modules[i].active){slot=(int)i;break;}if(slot<0){x86_dll_last_error=7;return 0;}
 uint32_t base=X86_DLL_BASE+(uint32_t)slot*X86_DLL_STRIDE;if(base+isz<base||base+isz>guest_vm_limit||!x86_mem_ensure_wasm(base+isz)||!x86_mem_region_add(base,isz,X86_MEM_READ|X86_MEM_WRITE|X86_MEM_EXEC,8u)){x86_dll_last_error=8;return 0;}
 for(uint32_t i=0;i<isz;i++)wr8(base+i,0);copy_bytes(base,f,hsz);
 for(uint16_t i=0;i<nsec;i++,sh+=40u){uint32_t va=rd32(sh+12u),vsz=rd32(sh+8u),raw=rd32(sh+20u),rawsz=rd32(sh+16u),mapped=vsz>rawsz?vsz:rawsz;if(va+mapped<va||va+mapped>isz||raw>sz||rawsz>sz-raw){x86_dll_last_error=9;return 0;}if(rawsz)copy_bytes(base+va,f+raw,rawsz);}
 if(!x86_dll_apply_relocs(base,isz,pref,rr,rs)){x86_dll_last_error=10;return 0;}
 uint32_t ok=0,bad=0; x86_dll_modules[slot]=(x86_dll_module_t){0}; x86_dll_modules[slot].active=1u; x86_dll_modules[slot].base=base; x86_dll_modules[slot].size=isz; x86_dll_modules[slot].preferred=pref; x86_dll_modules[slot].entry=entry; x86_dll_modules[slot].reloc_rva=rr; x86_dll_modules[slot].reloc_size=rs; x86_dll_modules[slot].export_rva=er; x86_dll_modules[slot].export_size=es; x86_dll_modules[slot].refcount=1u;
 if(er&&er+40u<=isz){uint32_t modrva=rd32(base+er+12u);if(modrva<isz){uint32_t p=base+modrva,j=0;for(;j<95u&&j<sizeof(x86_dll_modules[slot].name)-1u&&MEM8(p+j);j++)x86_dll_modules[slot].name[j]=(char)MEM8(p+j);x86_dll_modules[slot].name[j]=0;}}
 uint32_t rp=requested_name,j=0;for(;j<95u&&j<sizeof(x86_dll_modules[slot].requested_name)-1u&&MEM8(rp+j);j++)x86_dll_modules[slot].requested_name[j]=(char)MEM8(rp+j);x86_dll_modules[slot].requested_name[j]=0;
 x86_dll_resolve_imports(base,isz,ir,is,&ok,&bad);x86_dll_modules[slot].imports_resolved=ok;x86_dll_modules[slot].imports_failed=bad;x86_dll_last_base=base;x86_dll_last_error=0;return slot+1;
}
static int x86_dll_register(uint32_t name,uint32_t data,uint32_t size){
 uint32_t np=x86_dll_basename_ptr(name);if(!np||!size||!x86_mem_region_find(data,size,X86_MEM_READ)){x86_dll_last_error=11;return 0;}
 for(uint32_t i=0;i<X86_DLL_MAX_RESOURCES;i++)if(x86_dll_resources[i].active&&x86_dll_name_equal(np,x86_dll_resources[i].name)){
  /* Duplicate .zdll registration: keep the first valid resource and discard the later one. */
  x86_dll_last_error=0;
  return 1;
}
 for(uint32_t i=0;i<X86_DLL_MAX_RESOURCES;i++)if(!x86_dll_resources[i].active){x86_dll_resources[i].active=1;x86_dll_resources[i].data=data;x86_dll_resources[i].size=size;uint32_t j=0;for(;j<95u&&j<sizeof(x86_dll_resources[i].name)-1u&&MEM8(np+j);j++)x86_dll_resources[i].name[j]=(char)MEM8(np+j);x86_dll_resources[i].name[j]=0;return 1;}
 x86_dll_last_error=12;return 0;
}
static uint32_t x86_dll_load_registered(uint32_t name){
 uint32_t np=x86_dll_basename_ptr(name);int li=x86_dll_find_loaded(np);if(li>=0){x86_dll_modules[li].refcount++;return x86_dll_modules[li].base;}
 for(uint32_t i=0;i<X86_DLL_MAX_RESOURCES;i++)if(x86_dll_resources[i].active&&x86_dll_name_equal(np,x86_dll_resources[i].name)){int slot=x86_dll_load_image(x86_dll_resources[i].data,x86_dll_resources[i].size,np);if(slot>0){x86_dll_rebind_all();return x86_dll_modules[slot-1].base;}return 0;}
 x86_dll_last_error=13;return 0;
}
static uint32_t x86_dll_module_for_name(uint32_t name){uint32_t p=x86_dll_basename_ptr(name);int i=x86_dll_find_loaded(p);if(i>=0)return x86_dll_modules[i].base;return x86_dll_ascii_module_name(p)?image_base:0;}
static void x86_dll_rebind_all(void){if(loaded)scan_imports();}

static int load_pe(uint32_t f,uint32_t sz){
 load_error=0;loaded=0;last_load_ptr=f;last_load_size=sz;
 crt_exited=0;crt_exit_code=0;crt_last_termination_kind=0u;crt_last_termination_caller=0u;
 crt_last_termination_return_eip=0u;crt_last_termination_target=0u;crt_last_termination_arg0=0u;
 crt_last_shim_index=0xFFFFFFFFu;crt_last_shim_caller=0u;crt_last_shim_target=0u;crt_last_shim_arg0=0u;crt_last_shim_argc=0u;crash_hit=0u;crash_return_eip=0u;crash_nframes=0u;crash_arg0=0u;
 x86_fs_base=X86_FS_TEB_BASE; x86_gs_base=X86_GS_TEB_BASE;
 requested_image_base=0;reloc_rva=reloc_size=import_rva=import_size=0;relocation_needed=0;dll_count=import_count=0;import_resolved=import_failed=0;last_import_dll=last_import_func=last_import_thunk=last_import_target=0;last_failed_import_dll=last_failed_import_func=0;x86_gdr_reset();last_unresolved_gdr=0xFFFFFFFFu;mouse_clicks=0;mouse_right_clicks=0;mouse_middle_clicks=0;mouse_moves=0;surface_width=640;surface_height=360;
 if(sz<0x40u){load_error=1;return-1;} if(rd16(f)!=0x5a4du){load_error=2;return-1;}
 uint32_t pe=rd32(f+0x3cu); if(pe>sz-4u){load_error=3;return-2;} if(pe+24u>sz){load_error=4;return-2;}
 if(rd32(f+pe)!=0x4550u){load_error=5;return-2;}
 uint16_t mach=rd16(f+pe+4),nsec=rd16(f+pe+6),optsz=rd16(f+pe+20);
 if(mach!=0x14cu){load_error=6;return-3;} if(optsz<224u){load_error=7;return-3;}
 uint32_t oh=f+pe+24u; if(oh+optsz>f+sz){load_error=8;return-3;} if(rd16(oh)!=0x10bu){load_error=9;return-3;}
 uint32_t szimg=rd32(oh+56u),szhdr=rd32(oh+60u),ep=rd32(oh+16u),reqbase=rd32(oh+28u);
 uint32_t dirs=rd32(oh+92u);
 if(szimg<0x1000u||szimg>0x10000000u){load_error=10;return-4;} if(szhdr>sz||szhdr>szimg){load_error=11;return-4;}
 requested_image_base=reqbase; image_base=IMAGE_BASE; image_size=szimg; entry=ep;
 relocation_needed=(requested_image_base!=image_base)?1u:0u;
 if(dirs>1u){import_rva=rd32(oh+96u+8u);import_size=rd32(oh+96u+12u);}
 if(dirs>5u){reloc_rva=rd32(oh+96u+40u);reloc_size=rd32(oh+96u+44u);}
 uint32_t sh=oh+optsz;
 if(sh<f||sh>f+sz||(uint64_t)nsec*40u>(uint64_t)(f+sz-sh)){load_error=12;return-5;}
 /* The shell normally stages the PE around 0x00100000 while the guest image
  * begins at 0x00400000. Large PE files therefore overlap their own source
  * buffer. Zeroing/copying the image in place can destroy later section data
  * before it is read. Stage the source first when the two ranges overlap. */
 uint32_t source=f;
 uint32_t source_scratch=0;
 uint64_t src_end=(uint64_t)f+sz;
 uint64_t dst_end=(uint64_t)image_base+image_size;
 if((uint64_t)f<dst_end&&(uint64_t)image_base<src_end){
  const uint32_t scratch_base=0x0E000000u;
  if((uint64_t)scratch_base+sz>0x10000000ull){load_error=17;return-8;}
  if(!x86_mem_ensure_wasm(scratch_base+sz)){load_error=17;return-8;}
  copy_bytes(scratch_base,f,sz);
  source=scratch_base;source_scratch=1;
 }
 uint32_t sh_source=source+(sh-(uint32_t)f);
 for(uint32_t i=0;i<image_size;i++)wr8(image_base+i,0);
 copy_bytes(image_base,source,szhdr);
 sh=sh_source; /* the original header may live inside the image range that was just zeroed */
 for(uint16_t i=0;i<nsec;i++,sh+=40u){
  uint32_t va=rd32(sh+12u),vsz=rd32(sh+8u),raw=rd32(sh+20u),rawsz=rd32(sh+16u);
  uint32_t mapped=vsz>rawsz?vsz:rawsz;
  if((uint64_t)va+mapped>(uint64_t)image_size){load_error=13;return-5;}
  if(raw>sz||rawsz>sz-raw){load_error=14;return-5;}
  if(rawsz)copy_bytes(image_base+va,source+raw,rawsz);
 }
 (void)source_scratch;
 if(ep>=image_size){load_error=15;return-6;}
 if(import_rva&&import_size)scan_imports();
 x86_mem_reset(); x86_mem_register_image();
 /* Minimal guest TEB/PEB backing for Windows x86 FS/GS references. */
 if(!x86_mem_ensure_wasm(X86_GS_TEB_BASE+0x1000u)){load_error=16;return-7;}
 if(!x86_mem_region_add(X86_FS_TEB_BASE,0x1000u,X86_MEM_READ|X86_MEM_WRITE,7u)){load_error=16;return-7;}
 if(!x86_mem_region_add(X86_GS_TEB_BASE,0x1000u,X86_MEM_READ|X86_MEM_WRITE,7u)){load_error=16;return-7;}
 for(uint32_t i=0;i<0x1000u;i++){wr8(X86_FS_TEB_BASE+i,0);wr8(X86_GS_TEB_BASE+i,0);}
 wr32(X86_FS_TEB_BASE+0x18u,X86_FS_TEB_BASE);
 wr32(X86_FS_TEB_BASE+0x30u,X86_FS_TEB_BASE+0x100u);
 wr32(X86_GS_TEB_BASE+0x18u,X86_GS_TEB_BASE);
 /* Ensure the guest stack has real WASM backing before the first PUSH. */
 if(!x86_mem_ensure_wasm(X86_STACK_TOP)){load_error=16;return-7;}
 if(!x86_mem_region_add(X86_STACK_BASE,X86_STACK_SIZE,X86_MEM_READ|X86_MEM_WRITE,6u)){load_error=16;return-7;}
 x87_init_state(); xmm_reset();
 loaded=1;eip=image_base+entry;regs[R_ESP]=X86_STACK_TOP;
/* A PE entrypoint is invoked by the runtime rather than by a guest CALL. Seed a
 * synthetic return address so C fixtures whose entrypoint is main() can RET cleanly. */
if(!x86_stack_push32(X86_ENTRY_RETURN_SENTINEL)){loaded=0;load_error=16;return-7;}
apilog_count=0;{uint32_t iend=image_base+image_size;guest_heap=(iend>GUEST_HEAP_BASE&&iend<GUEST_HEAP_LIMIT)?((iend+0xFFFu)&~0xFFFu):GUEST_HEAP_BASE;}halted=0;cpu_error=0;steps=0;eflags=0x2;decoded_prefixes=0;decoded_operand16=0;last_decoded_map=0;last_decoded_opcode=0;last_decoded_length=0;last_decoded_modrm=0;last_decoded_has_modrm=0;last_dispatch_id=0;last_dispatch_count=0;last_indirect_slot=0;last_indirect_target=0;last_unresolved_gdr=0xFFFFFFFFu;
x86_first_fault_eip=0;x86_last_fault_eip=0;x86_first_fault_count=0;
x86_control_fault_kind=0;x86_control_fault_eip=0;x86_control_fault_next_eip=0;x86_control_fault_target=0;x86_control_fault_slot=0;x86_control_fault_opcode=0;x86_control_fault_modrm=0;
x86_trace_reset();x86_profile_clear();
 x87_init_state(); xmm_reset();
 legacy_execution_count=0;
 loghex("X86 requested image base=",requested_image_base);
 loghex("X86 mapped image base=",image_base);
 loghex("X86 entry=",eip);
 return 0;
}

__attribute__((export_name("zwasm_init"))) int zwasm_init(void){
 crt_errno=0;crt_last_error=0;crt_started=1;crt_exited=0;crt_exit_code=0;
 crt_last_termination_kind=0u;crt_last_termination_caller=0u;crt_last_termination_return_eip=0u;
 crt_last_termination_target=0u;crt_last_termination_arg0=0u;
 crt_last_shim_index=0xFFFFFFFFu;crt_last_shim_caller=0u;crt_last_shim_target=0u;crt_last_shim_arg0=0u;crt_last_shim_argc=0u;crash_hit=0u;crash_return_eip=0u;crash_nframes=0u;crash_arg0=0u;
 crt_atexit_count=0;crt_last_atexit_result=0;crt_atexit_running=0;
 x86_fs_reset();
 x86_reg_reset();
 /* DLL resources/modules belong to the loaded package, not to CRT process state.
  * Do not erase them here: the browser/package loader may register DLLs before
  * CRT startup, and clearing them made every bundled DLL disappear just before
  * import rebinding (dll_count=0, followed by hundreds of false unresolved imports). */

 heap=al4((uint32_t)(uintptr_t)__heap_base);x86_flow_head=0;x86_flow_count=0;guest_heap=GUEST_HEAP_BASE;x86_mem_reset();guest_vm=0x02000000u;last_virtual_alloc=0;last_virtual_alloc_size=0;virtual_free_count=0;loaded=0;requested_image_base=0;reloc_rva=reloc_size=import_rva=import_size=0;relocation_needed=0;dll_count=0;import_count=0;steps=0;load_error=0;halted=0;cpu_error=0;eflags=0x2;surface_width=640;surface_height=360;
 for(int i=0;i<8;i++)regs[i]=0; decoded_prefixes=0;decoded_operand16=0; last_decoded_map=0;last_decoded_opcode=0;last_decoded_length=0;last_decoded_modrm=0;last_decoded_has_modrm=0;last_dispatch_id=0;last_dispatch_count=0;last_indirect_slot=0;last_indirect_target=0;last_unresolved_gdr=0xFFFFFFFFu;x86_trace_reset();x86_profile_clear(); message_count=0;message_last=0;message_quit=0;mouse_clicks=0;mouse_right_clicks=0;mouse_middle_clicks=0;mouse_moves=0;
loglit("XWASM X86 Runtime v0.9");
loglit("PE32 + decoder CPU + guest memory regions + USER32/GDI32 + browser window/message/input + audio bridge");return 0;
}
__attribute__((export_name("x86_get_runtime_version"))) uint32_t x86_get_runtime_version(void){return 0x00090001u;}
__attribute__((export_name("x86_get_last_module_handle_arg"))) uint32_t x86_get_last_module_handle_arg(void){return crt_last_shim_arg0;}
__attribute__((export_name("x86_get_last_module_handle_result"))) uint32_t x86_get_last_module_handle_result(void){return (crt_last_shim_index==SHIM_GetModuleHandleA||crt_last_shim_index==SHIM_GetModuleHandleW)?regs[R_EAX]:0u;}
__attribute__((export_name("x86_debug_probe"))) uint32_t x86_debug_probe(int32_t p){return rd16((uint32_t)p);}
__attribute__((export_name("x86_load_pe"))) int x86_load_pe(int32_t p,int32_t n){return load_pe((uint32_t)p,(uint32_t)n);}
__attribute__((export_name("x86_dll_register_image"))) int x86_dll_register_image(int32_t name,int32_t data,int32_t size){return x86_dll_register((uint32_t)name,(uint32_t)data,(uint32_t)size);}
__attribute__((export_name("x86_dll_load_registered"))) uint32_t x86_dll_load_registered_export(int32_t name){return x86_dll_load_registered((uint32_t)name);}
__attribute__((export_name("x86_dll_rebind_imports"))) int x86_dll_rebind_imports(void){x86_dll_rebind_all();return (int)import_failed;}
__attribute__((export_name("x86_dll_get_last_error"))) uint32_t x86_dll_get_last_error(void){return x86_dll_last_error;}
__attribute__((export_name("x86_dll_get_count"))) uint32_t x86_dll_get_count(void){uint32_t n=0;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active)n++;return n;}
__attribute__((export_name("x86_dll_get_base"))) uint32_t x86_dll_get_base(uint32_t index){uint32_t n=0;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active){if(n++==index)return x86_dll_modules[i].base;}return 0;}
__attribute__((export_name("x86_dll_get_size"))) uint32_t x86_dll_get_size(uint32_t index){uint32_t n=0;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active){if(n++==index)return x86_dll_modules[i].size;}return 0;}
__attribute__((export_name("x86_dll_get_entry"))) uint32_t x86_dll_get_entry(uint32_t index){uint32_t n=0;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active){if(n++==index)return x86_dll_modules[i].base+x86_dll_modules[i].entry;}return 0;}
__attribute__((export_name("x86_dll_get_import_failed"))) uint32_t x86_dll_get_import_failed(uint32_t index){uint32_t n=0;for(uint32_t i=0;i<X86_DLL_MAX_MODULES;i++)if(x86_dll_modules[i].active){if(n++==index)return x86_dll_modules[i].imports_failed;}return 0;}

__attribute__((export_name("x86_run"))) int x86_run(int32_t max_steps){
 if(!loaded)return -20; if(halted)return 1; if(max_steps<1)max_steps=1;
 for(int32_t i=0;i<max_steps&&!halted;i++){
  uint32_t espw_eip=eip;
  int r=cpu_step();
  {uint32_t e=regs[R_ESP],d=e>espw_prev?e-espw_prev:espw_prev-e;if(espw_prev&&d>0x10000u)x86_espw_event(espw_eip,espw_prev,e);espw_prev=e;}
  if(r<0){
   /* A CPU fault is terminal for this run, but the machine state remains
    * intact for diagnostics: EIP, decoded opcode, trace, registers, stack,
    * memory-fault counters, and cpu_error are all still queryable. */
   halted=1;
   return r;
  }
  /* Some checked helpers report a guest-memory fault through cpu_error while
   * returning a neutral value to their instruction handler. Do not execute
   * another guest instruction: that would overwrite the first-fault evidence
   * and can turn a bad load (for example MOV EAX,[0]) into a later ESP fault. */
  if(cpu_error>=0xE100u){
   halted=1;
   return -49;
  }
  if(eip==X86_ENTRY_RETURN_SENTINEL){halted=1;break;}
 }
 return halted?1:0;
}

/* ---- diagnostics: stack ---- */
__attribute__((export_name("x86_get_trace_post_esp"))) uint32_t x86_get_trace_post_esp(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_esp[i]:0;}
__attribute__((export_name("x86_get_trace_post_ebp"))) uint32_t x86_get_trace_post_ebp(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_ebp[i]:0;}
__attribute__((export_name("x86_get_shadow_stat"))) uint32_t x86_get_shadow_stat(uint32_t f){
 switch(f){case 0:return sh_top;case 1:return sh_overflow;case 2:return sh_calls;case 3:return sh_rets;case 4:return sh_mm_count;case 5:return sh_um_count;case 6:return espw_count;}
 return 0;}
/* kind: 0 first mismatch, 1 last mismatch, 2 first unmatched, 3 last unmatched; field 0..7 = ret_eip,target,esp,expected esp,callee,site,steps,depth */
__attribute__((export_name("x86_get_shadow_event"))) uint32_t x86_get_shadow_event(uint32_t kind,uint32_t f){
 if(f>=8u)return 0;
 switch(kind){case 0:return sh_mm[f];case 1:return sh_mm_last[f];case 2:return sh_um[f];case 3:return sh_um_last[f];}
 return 0;}
/* i = frame index from the bottom of the shadow stack; field 0 callee, 1 call site, 2 return address, 3 esp after push */
__attribute__((export_name("x86_get_shadow_frame"))) uint32_t x86_get_shadow_frame(uint32_t i,uint32_t f){
 if(i>=sh_top||i>=X86_SHADOW_DEPTH)return 0;
 switch(f){case 0:return sh_callee[i];case 1:return sh_site[i];case 2:return sh_ret[i];case 3:return sh_esp[i];}
 return 0;}
__attribute__((export_name("x86_get_espw_event"))) uint32_t x86_get_espw_event(uint32_t k,uint32_t f){return (k<X86_ESPW_EVENTS&&f<6u)?espw_ev[k][f]:0;}
/* field 0 eip, 1 opcode, 2 esp, 3 ebp */
__attribute__((export_name("x86_get_espw_snap"))) uint32_t x86_get_espw_snap(uint32_t k,uint32_t i,uint32_t f){
 if(k>=X86_ESPW_EVENTS||i>=X86_ESPW_SNAP)return 0;
 switch(f){case 0:return espw_snap_eip[k][i];case 1:return espw_snap_op[k][i];case 2:return espw_snap_esp[k][i];case 3:return espw_snap_ebp[k][i];}
 return 0;}

__attribute__((export_name("x86_get_apilog_count"))) uint32_t x86_get_apilog_count(void){return apilog_count;}
/* i counts back from the newest call (0 = newest). field: 0 target,1 caller,2 ret,3 step,4..7 args */
__attribute__((export_name("x86_get_apilog"))) uint32_t x86_get_apilog(uint32_t i,uint32_t f){
 if(i>=apilog_count||i>=X86_APILOG_DEPTH)return 0;
 uint32_t k=(apilog_count-1u-i)%X86_APILOG_DEPTH;
 switch(f){case 0:return apilog_target[k];case 1:return apilog_caller[k];case 2:return apilog_ret[k];case 3:return apilog_step[k];}
 return (f>=4u&&f<8u)?apilog_arg[k][f-4u]:0;}
/* name character j of the shim behind entry i (0 when the call was not a table shim or j is past the end) */
__attribute__((export_name("x86_get_apilog_name_char"))) uint32_t x86_get_apilog_name_char(uint32_t i,uint32_t j){
 if(i>=apilog_count||i>=X86_APILOG_DEPTH)return 0;
 uint32_t t=apilog_target[(apilog_count-1u-i)%X86_APILOG_DEPTH];
 if(t<API_SHIM_BASE)return 0;
 uint32_t idx=(t-API_SHIM_BASE)>>2;
 if(idx>=sizeof(shim_tab)/sizeof(shim_tab[0]))return 0;
 const char*n=shim_tab[idx].name;
 for(uint32_t q=0;q<=j;q++){if(!n[q])return 0;}
 return (uint8_t)n[j];}
__attribute__((export_name("x86_get_eip"))) uint32_t x86_get_eip(void){return eip;}
__attribute__((export_name("x86_get_flow_count"))) uint32_t x86_get_flow_count(void){return x86_flow_count;}
__attribute__((export_name("x86_get_flow_eip"))) uint32_t x86_get_flow_eip(uint32_t i){if(i>=x86_flow_count)return 0;return x86_flow_eip[(x86_flow_head+x86_flow_count-1u-i)%X86_FLOW_DEPTH];}
__attribute__((export_name("x86_get_flow_esp"))) uint32_t x86_get_flow_esp(uint32_t i){if(i>=x86_flow_count)return 0;return x86_flow_esp[(x86_flow_head+x86_flow_count-1u-i)%X86_FLOW_DEPTH];}
__attribute__((export_name("x86_get_flow_ebp"))) uint32_t x86_get_flow_ebp(uint32_t i){if(i>=x86_flow_count)return 0;return x86_flow_ebp[(x86_flow_head+x86_flow_count-1u-i)%X86_FLOW_DEPTH];}
__attribute__((export_name("x86_get_flow_opcode"))) uint32_t x86_get_flow_opcode(uint32_t i){if(i>=x86_flow_count)return 0;return x86_flow_opcode[(x86_flow_head+x86_flow_count-1u-i)%X86_FLOW_DEPTH];}
__attribute__((export_name("x86_get_steps"))) uint32_t x86_get_steps(void){return steps;}
__attribute__((export_name("x86_get_eax"))) uint32_t x86_get_eax(void){return regs[R_EAX];}
__attribute__((export_name("x86_get_ecx"))) uint32_t x86_get_ecx(void){return regs[R_ECX];}
__attribute__((export_name("x86_get_edx"))) uint32_t x86_get_edx(void){return regs[R_EDX];}
__attribute__((export_name("x86_get_ebx"))) uint32_t x86_get_ebx(void){return regs[R_EBX];}
__attribute__((export_name("x86_get_esp"))) uint32_t x86_get_esp(void){return regs[R_ESP];}
__attribute__((export_name("x86_get_stack_faults"))) uint32_t x86_get_stack_faults(void){return x86_mem_faults;}
__attribute__((export_name("x86_get_last_stack_fault_esp"))) uint32_t x86_get_last_stack_fault_esp(void){return x86_last_stack_fault_esp;}
__attribute__((export_name("x86_get_last_stack_fault_eip"))) uint32_t x86_get_last_stack_fault_eip(void){return x86_last_stack_fault_eip;}
__attribute__((export_name("x86_get_last_stack_fault_kind"))) uint32_t x86_get_last_stack_fault_kind(void){return x86_last_stack_fault_kind;}
__attribute__((export_name("x86_get_stack_region_base"))) uint32_t x86_get_stack_region_base(void){return X86_STACK_BASE;}
__attribute__((export_name("x86_get_stack_region_top"))) uint32_t x86_get_stack_region_top(void){return X86_STACK_TOP;}
__attribute__((export_name("x86_get_first_fault_eip"))) uint32_t x86_get_first_fault_eip(void){return x86_first_fault_eip;}
__attribute__((export_name("x86_get_last_fault_eip"))) uint32_t x86_get_last_fault_eip(void){return x86_last_fault_eip;}
__attribute__((export_name("x86_get_first_fault_count"))) uint32_t x86_get_first_fault_count(void){return x86_first_fault_count;}
__attribute__((export_name("x86_get_control_fault_kind"))) uint32_t x86_get_control_fault_kind(void){return x86_control_fault_kind;}
__attribute__((export_name("x86_get_control_fault_eip"))) uint32_t x86_get_control_fault_eip(void){return x86_control_fault_eip;}
__attribute__((export_name("x86_get_control_fault_next_eip"))) uint32_t x86_get_control_fault_next_eip(void){return x86_control_fault_next_eip;}
__attribute__((export_name("x86_get_control_fault_target"))) uint32_t x86_get_control_fault_target(void){return x86_control_fault_target;}
__attribute__((export_name("x86_get_control_fault_slot"))) uint32_t x86_get_control_fault_slot(void){return x86_control_fault_slot;}
__attribute__((export_name("x86_get_control_fault_opcode"))) uint32_t x86_get_control_fault_opcode(void){return x86_control_fault_opcode;}
__attribute__((export_name("x86_get_control_fault_modrm"))) uint32_t x86_get_control_fault_modrm(void){return x86_control_fault_modrm;}
__attribute__((export_name("x86_get_ebp"))) uint32_t x86_get_ebp(void){return regs[R_EBP];}
__attribute__((export_name("x86_get_esi"))) uint32_t x86_get_esi(void){return regs[R_ESI];}
__attribute__((export_name("x86_get_edi"))) uint32_t x86_get_edi(void){return regs[R_EDI];}
__attribute__((export_name("x86_get_eflags"))) uint32_t x86_get_eflags(void){return eflags;}
__attribute__((export_name("x86_get_fs_base"))) uint32_t x86_get_fs_base(void){return x86_fs_base;}
__attribute__((export_name("x86_get_gs_base"))) uint32_t x86_get_gs_base(void){return x86_gs_base;}
__attribute__((export_name("x86_get_halted"))) uint32_t x86_get_halted(void){return halted;}
__attribute__((export_name("x86_get_cpu_error"))) uint32_t x86_get_cpu_error(void){return cpu_error;}
__attribute__((export_name("x86_get_last_decoded_map"))) uint32_t x86_get_last_decoded_map(void){return last_decoded_map;}
__attribute__((export_name("x86_get_last_decoded_opcode"))) uint32_t x86_get_last_decoded_opcode(void){return last_decoded_opcode;}
__attribute__((export_name("x86_get_last_decoded_length"))) uint32_t x86_get_last_decoded_length(void){return last_decoded_length;}
__attribute__((export_name("x86_get_last_decoded_modrm"))) uint32_t x86_get_last_decoded_modrm(void){return last_decoded_modrm;}
__attribute__((export_name("x86_get_last_decoded_has_modrm"))) uint32_t x86_get_last_decoded_has_modrm(void){return last_decoded_has_modrm;}
__attribute__((export_name("x86_profile_set_enabled"))) void x86_profile_set_enabled(uint32_t enabled){x86_profile_enabled=enabled?1u:0u;}
__attribute__((export_name("x86_get_profile_enabled"))) uint32_t x86_get_profile_enabled(void){return x86_profile_enabled;}
__attribute__((export_name("x86_profile_reset"))) void x86_profile_reset(void){x86_profile_clear();}
__attribute__((export_name("x86_get_profile_count"))) uint32_t x86_get_profile_count(void){return x86_profile_count;}
__attribute__((export_name("x86_get_profile_used"))) uint32_t x86_get_profile_used(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].used:0;}
__attribute__((export_name("x86_get_profile_map"))) uint32_t x86_get_profile_map(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].map:0;}
__attribute__((export_name("x86_get_profile_opcode"))) uint32_t x86_get_profile_opcode(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].opcode:0;}
__attribute__((export_name("x86_get_profile_modrm"))) uint32_t x86_get_profile_modrm(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].modrm:0;}
__attribute__((export_name("x86_get_profile_has_modrm"))) uint32_t x86_get_profile_has_modrm(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].has_modrm:0;}
__attribute__((export_name("x86_get_profile_dispatch"))) uint32_t x86_get_profile_dispatch(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].dispatch:0;}
__attribute__((export_name("x86_get_profile_count_at"))) uint32_t x86_get_profile_count_at(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].count:0;}
__attribute__((export_name("x86_get_profile_first_eip"))) uint32_t x86_get_profile_first_eip(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].first_eip:0;}
__attribute__((export_name("x86_get_profile_last_eip"))) uint32_t x86_get_profile_last_eip(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].last_eip:0;}
__attribute__((export_name("x86_get_profile_min_length"))) uint32_t x86_get_profile_min_length(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].min_length:0;}
__attribute__((export_name("x86_get_profile_max_length"))) uint32_t x86_get_profile_max_length(uint32_t i){return i<X86_PROFILE_SLOTS?x86_profile[i].max_length:0;}
__attribute__((export_name("x86_get_profile_semantic_id_len"))) uint32_t x86_get_profile_semantic_id_len(uint32_t i){uint32_t n=0;if(i>=X86_PROFILE_SLOTS)return 0;while(n<X86_SEMANTIC_ID_MAX&&x86_profile[i].semantic[n])n++;return n;}
__attribute__((export_name("x86_get_profile_semantic_id_char"))) uint32_t x86_get_profile_semantic_id_char(uint32_t i,uint32_t n){return i<X86_PROFILE_SLOTS&&n<X86_SEMANTIC_ID_MAX?(uint8_t)x86_profile[i].semantic[n]:0;}
__attribute__((export_name("x86_get_last_dispatch_id"))) uint32_t x86_get_last_dispatch_id(void){return last_dispatch_id;}
__attribute__((export_name("x86_get_last_dispatch_count"))) uint32_t x86_get_last_dispatch_count(void){return last_dispatch_count;}
__attribute__((export_name("x86_get_last_semantic_id_ptr"))) uint32_t x86_get_last_semantic_id_ptr(void){return (uint32_t)(uintptr_t)last_decoded_semantic_id;}
__attribute__((export_name("x86_get_last_semantic_id_len"))) uint32_t x86_get_last_semantic_id_len(void){uint32_t n=0;while(n<X86_SEMANTIC_ID_MAX&&last_decoded_semantic_id[n])++n;return n;}
__attribute__((export_name("x86_get_last_semantic_id_char"))) uint32_t x86_get_last_semantic_id_char(uint32_t n){return n<X86_SEMANTIC_ID_MAX?(uint8_t)last_decoded_semantic_id[n]:0;}
__attribute__((export_name("x86_get_trace_semantic_id_char"))) uint32_t x86_get_trace_semantic_id_char(uint32_t i,uint32_t n){return i<X86_TRACE_DEPTH&&n<X86_SEMANTIC_ID_MAX?(uint8_t)trace_semantic_id[i][n]:0;}
__attribute__((export_name("x86_get_trace_semantic_id_ptr"))) uint32_t x86_get_trace_semantic_id_ptr(uint32_t i){return i<X86_TRACE_DEPTH?(uint32_t)(uintptr_t)trace_semantic_id[i]:0;}
__attribute__((export_name("x86_get_trace_semantic_id_len"))) uint32_t x86_get_trace_semantic_id_len(uint32_t i){uint32_t n=0;if(i>=X86_TRACE_DEPTH)return 0;while(n<X86_SEMANTIC_ID_MAX&&trace_semantic_id[i][n])++n;return n;}

/* Independent architectural RCR oracle used by the test shell.  This is
 * deliberately separate from guest state so a failed game fixture cannot
 * mask a rotate-through-carry regression. */
__attribute__((export_name("x86_rcr32_self_test")))
uint32_t x86_rcr32_self_test(void){
 uint32_t failures=0;
 const uint32_t values[4]={0x80000000u,0x80000000u,0x00000001u,0xFFFFFFFFu};
 const uint32_t carries[4]={0u,1u,1u,0u};
 const uint32_t counts[4]={1u,1u,1u,31u};
 const uint32_t expected[4]={0x40000000u,0xC0000000u,0x80000000u,0xFFFFFFFDu};
 const uint32_t expected_cf[4]={0u,0u,1u,1u};
 for(uint32_t i=0;i<4u;i++){
  uint32_t count=counts[i]&31u;
  uint64_t x=((uint64_t)carries[i]<<32)|values[i];
  x=((x>>count)|(x<<(33u-count)))&0x1FFFFFFFFull;
  if((uint32_t)x!=expected[i] || (uint32_t)((x>>32)&1u)!=expected_cf[i]) failures|=(1u<<i);
 }
 return failures;
}

/* Forward-only instruction preflight. This deliberately decodes without executing
 * guest instructions, so the browser shell can find likely instruction gaps before
 * a real run reaches them. When a form is missing, the scanner performs a speculative
 * byte resynchronization (up to 15 bytes) and marks the result as a POTENTIAL gap. */
#define X86_PREFLIGHT_DEPTH 512u
#define X86_PREFLIGHT_SEM_MAX 64u
static uint32_t preflight_count=0,preflight_mines=0,preflight_start=0,preflight_start_reason=0;
/* start_reason: 0=current/requested code, 1=stack return address, 2=recent trace code, 3=PE entry */
static uint32_t preflight_eip[X86_PREFLIGHT_DEPTH],preflight_next_eip[X86_PREFLIGHT_DEPTH];
static uint32_t preflight_opcode[X86_PREFLIGHT_DEPTH],preflight_map[X86_PREFLIGHT_DEPTH];
static uint32_t preflight_modrm[X86_PREFLIGHT_DEPTH],preflight_has_modrm[X86_PREFLIGHT_DEPTH];
static uint32_t preflight_length[X86_PREFLIGHT_DEPTH],preflight_status[X86_PREFLIGHT_DEPTH];
static char preflight_semantic[X86_PREFLIGHT_DEPTH][X86_PREFLIGHT_SEM_MAX];

static void x86_preflight_semantic_copy(char *dst,const char *src){
 uint32_t i=0;if(!src)src="MISSING";
 for(;i+1u<X86_PREFLIGHT_SEM_MAX&&src[i];i++)dst[i]=src[i];
 dst[i]=0;
}
static uint32_t x86_preflight_resync(uint32_t pc){
 for(uint32_t delta=1u;delta<=15u;delta++){
  uint32_t candidate=pc+delta;
  if(!x86_mem_region_find(candidate,1u,X86_MEM_READ|X86_MEM_EXEC))break;
  x86_decoded_t probe;
  eip=candidate;
  int rc=x86_decode_instruction(&probe);
  (void)rc;
  if(probe.start!=candidate)continue;
  if(rc==0&&probe.cursor>candidate)return candidate;
 }
 return pc+1u;
}
__attribute__((export_name("x86_preflight_scan")))
uint32_t x86_preflight_scan(uint32_t start_eip,uint32_t max_instructions){
 uint32_t saved_eip=eip,saved_error=cpu_error,saved_halted=halted;
 preflight_count=0;preflight_mines=0;preflight_start=0;preflight_start_reason=0;
 uint32_t pc=start_eip?start_eip:eip;
 if(!x86_mem_region_find(pc,1u,X86_MEM_READ|X86_MEM_EXEC)){
  if(x86_mem_region_find(regs[R_ESP],4u,X86_MEM_READ)){
   uint32_t ret=rd32(regs[R_ESP]);
   if(x86_mem_region_find(ret,1u,X86_MEM_READ|X86_MEM_EXEC)){pc=ret;preflight_start_reason=1u;}
  }
  if(preflight_start_reason==0u){
   for(uint32_t back=0;back<trace_count;back++){
    uint32_t ti=(trace_head+X86_TRACE_DEPTH-1u-back)%X86_TRACE_DEPTH;
    uint32_t cand=trace_eip[ti];
    if(x86_mem_region_find(cand,1u,X86_MEM_READ|X86_MEM_EXEC)){pc=cand;preflight_start_reason=2u;break;}
   }
  }
  if(preflight_start_reason==0u){
   uint32_t cand=image_base+entry;
   if(x86_mem_region_find(cand,1u,X86_MEM_READ|X86_MEM_EXEC)){pc=cand;preflight_start_reason=3u;}
  }
 }
 if(!x86_mem_region_find(pc,1u,X86_MEM_READ|X86_MEM_EXEC)){eip=saved_eip;cpu_error=saved_error;halted=saved_halted;return 0;}
 preflight_start=pc;
 if(max_instructions>X86_PREFLIGHT_DEPTH)max_instructions=X86_PREFLIGHT_DEPTH;
 for(uint32_t n=0;n<max_instructions;n++){
  if(!x86_mem_region_find(pc,1u,X86_MEM_READ|X86_MEM_EXEC))break;
  x86_decoded_t d;
  eip=pc;
  int rc=x86_decode_instruction(&d);
  uint32_t idx=preflight_count++;
  preflight_eip[idx]=d.start;
  preflight_opcode[idx]=d.opcode;
  preflight_map[idx]=d.map;
  preflight_modrm[idx]=d.modrm;
  preflight_has_modrm[idx]=d.has_modrm;
  preflight_status[idx]=(rc==0)?0u:((rc==-2)?1u:2u);
  preflight_length[idx]=(rc==0&&d.cursor>d.start)?d.cursor-d.start:0u;
  x86_preflight_semantic_copy(preflight_semantic[idx],rc==0&&d.entry?d.entry->id:"MISSING");
  uint32_t next=(rc==0&&d.cursor>d.start)?d.cursor:x86_preflight_resync(pc);
  preflight_next_eip[idx]=next;
  if(rc==-2)preflight_mines++;
  if(next<=pc)break;
  pc=next;
 }
 eip=saved_eip;cpu_error=saved_error;halted=saved_halted;
 return preflight_count;
}
__attribute__((export_name("x86_get_preflight_count")))
uint32_t x86_get_preflight_count(void){return preflight_count;}
__attribute__((export_name("x86_get_preflight_mines")))
uint32_t x86_get_preflight_mines(void){return preflight_mines;}
__attribute__((export_name("x86_get_preflight_start")))
uint32_t x86_get_preflight_start(void){return preflight_start;}
__attribute__((export_name("x86_get_preflight_start_reason")))
uint32_t x86_get_preflight_start_reason(void){return preflight_start_reason;}
__attribute__((export_name("x86_get_preflight_eip")))
uint32_t x86_get_preflight_eip(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_eip[i]:0;}
__attribute__((export_name("x86_get_preflight_next_eip")))
uint32_t x86_get_preflight_next_eip(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_next_eip[i]:0;}
__attribute__((export_name("x86_get_preflight_opcode")))
uint32_t x86_get_preflight_opcode(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_opcode[i]:0;}
__attribute__((export_name("x86_get_preflight_map")))
uint32_t x86_get_preflight_map(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_map[i]:0;}
__attribute__((export_name("x86_get_preflight_modrm")))
uint32_t x86_get_preflight_modrm(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_modrm[i]:0;}
__attribute__((export_name("x86_get_preflight_has_modrm")))
uint32_t x86_get_preflight_has_modrm(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_has_modrm[i]:0;}
__attribute__((export_name("x86_get_preflight_length")))
uint32_t x86_get_preflight_length(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_length[i]:0;}
__attribute__((export_name("x86_get_preflight_status")))
uint32_t x86_get_preflight_status(uint32_t i){return i<X86_PREFLIGHT_DEPTH?preflight_status[i]:2u;}
__attribute__((export_name("x86_get_preflight_semantic_id_len")))
uint32_t x86_get_preflight_semantic_id_len(uint32_t i){
 uint32_t n=0;if(i>=X86_PREFLIGHT_DEPTH)return 0;
 while(n<X86_PREFLIGHT_SEM_MAX&&preflight_semantic[i][n])n++;
 return n;
}
__attribute__((export_name("x86_get_preflight_semantic_id_char")))
uint32_t x86_get_preflight_semantic_id_char(uint32_t i,uint32_t n){
 return i<X86_PREFLIGHT_DEPTH&&n<X86_PREFLIGHT_SEM_MAX?(uint8_t)preflight_semantic[i][n]:0;
}

__attribute__((export_name("x86_get_crash_hit"))) uint32_t x86_get_crash_hit(void){return crash_hit;}
__attribute__((export_name("x86_get_crash_return_eip"))) uint32_t x86_get_crash_return_eip(void){return crash_return_eip;}
__attribute__((export_name("x86_get_crash_frame_count"))) uint32_t x86_get_crash_frame_count(void){return crash_nframes;}
__attribute__((export_name("x86_get_crash_frame"))) uint32_t x86_get_crash_frame(uint32_t i){return i<16u?crash_frames[i]:0u;}
__attribute__((export_name("x86_get_crash_stack"))) uint32_t x86_get_crash_stack(uint32_t i){return i<32u?crash_stack[i]:0u;}
__attribute__((export_name("x86_get_trace_count"))) uint32_t x86_get_trace_count(void){return trace_count;}
__attribute__((export_name("x86_get_trace_index"))) uint32_t x86_get_trace_index(uint32_t n){if(n>=trace_count)return 0xFFFFFFFFu;return (trace_head+X86_TRACE_DEPTH-trace_count+n)%X86_TRACE_DEPTH;}
__attribute__((export_name("x86_get_trace_eip"))) uint32_t x86_get_trace_eip(uint32_t i){return i<X86_TRACE_DEPTH?trace_eip[i]:0;}
__attribute__((export_name("x86_get_trace_next_eip"))) uint32_t x86_get_trace_next_eip(uint32_t i){return i<X86_TRACE_DEPTH?trace_next_eip[i]:0;}
__attribute__((export_name("x86_get_trace_opcode"))) uint32_t x86_get_trace_opcode(uint32_t i){return i<X86_TRACE_DEPTH?trace_opcode[i]:0;}
__attribute__((export_name("x86_get_trace_flags"))) uint32_t x86_get_trace_flags(uint32_t i){return i<X86_TRACE_DEPTH?trace_flags[i]:0;}
__attribute__((export_name("x86_get_trace_eax"))) uint32_t x86_get_trace_eax(uint32_t i){return i<X86_TRACE_DEPTH?trace_eax[i]:0;}
__attribute__((export_name("x86_get_trace_ecx"))) uint32_t x86_get_trace_ecx(uint32_t i){return i<X86_TRACE_DEPTH?trace_ecx[i]:0;}
__attribute__((export_name("x86_get_trace_edx"))) uint32_t x86_get_trace_edx(uint32_t i){return i<X86_TRACE_DEPTH?trace_edx[i]:0;}
__attribute__((export_name("x86_get_trace_ebx"))) uint32_t x86_get_trace_ebx(uint32_t i){return i<X86_TRACE_DEPTH?trace_ebx[i]:0;}
__attribute__((export_name("x86_get_trace_post_eax"))) uint32_t x86_get_trace_post_eax(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_eax[i]:0;}
__attribute__((export_name("x86_get_trace_post_ecx"))) uint32_t x86_get_trace_post_ecx(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_ecx[i]:0;}
__attribute__((export_name("x86_get_trace_post_edx"))) uint32_t x86_get_trace_post_edx(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_edx[i]:0;}
__attribute__((export_name("x86_get_trace_post_ebx"))) uint32_t x86_get_trace_post_ebx(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_ebx[i]:0;}
__attribute__((export_name("x86_get_trace_post_flags"))) uint32_t x86_get_trace_post_flags(uint32_t i){return i<X86_TRACE_DEPTH?trace_post_flags[i]:0;}
__attribute__((export_name("x86_get_trace_dispatch"))) uint32_t x86_get_trace_dispatch(uint32_t i){return i<X86_TRACE_DEPTH?trace_dispatch[i]:0;}
__attribute__((export_name("x86_get_trace_failure_index"))) uint32_t x86_get_trace_failure_index(void){return trace_failure_index;}
__attribute__((export_name("x86_get_current_opcode")))
uint32_t x86_get_current_opcode(void){
 if(!loaded||!x86_mem_region_find(eip,1u,X86_MEM_READ))return 0xFFFFFFFFu;
 return (uint32_t)MEM8(eip);
}
__attribute__((export_name("x86_get_current_byte")))
uint32_t x86_get_current_byte(uint32_t index){
 if(!loaded||index>=32u||!x86_mem_region_find(eip+index,1u,X86_MEM_READ))return 0xFFFFFFFFu;
 return (uint32_t)MEM8(eip+index);
}
__attribute__((export_name("x86_get_stack_dword")))
uint32_t x86_get_stack_dword(uint32_t index){
 if(index>=16u)return 0xFFFFFFFFu;
 uint32_t p=regs[R_ESP]+index*4u;
 if(!x86_mem_region_find(p,4u,X86_MEM_READ))return 0xDEADFA11u;
 return rd32(p);
}
__attribute__((export_name("x86_get_x87_count")))
uint32_t x86_get_x87_count(void){return x87_count;}
__attribute__((export_name("x86_get_x87_control"))) uint32_t x86_get_x87_control(void){return x87_control;}
__attribute__((export_name("x86_get_x87_status"))) uint32_t x86_get_x87_status(void){return x87_status;}
__attribute__((export_name("x86_get_x87_trace_count"))) uint32_t x86_get_x87_trace_count(void){return x87_trace_count;}
__attribute__((export_name("x86_get_x87_trace_index"))) uint32_t x86_get_x87_trace_index(uint32_t n){if(n>=x87_trace_count)return 0xFFFFFFFFu;return (x87_trace_head+X87_TRACE_DEPTH-x87_trace_count+n)%X87_TRACE_DEPTH;}
__attribute__((export_name("x86_get_x87_trace_eip"))) uint32_t x86_get_x87_trace_eip(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_eip[i]:0;}
__attribute__((export_name("x86_get_x87_trace_opcode"))) uint32_t x86_get_x87_trace_opcode(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_opcode[i]:0;}
__attribute__((export_name("x86_get_x87_trace_modrm"))) uint32_t x86_get_x87_trace_modrm(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_modrm[i]:0;}
__attribute__((export_name("x86_get_x87_trace_count_before"))) uint32_t x86_get_x87_trace_count_before(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_count_before[i]:0;}
__attribute__((export_name("x86_get_x87_trace_count_after"))) uint32_t x86_get_x87_trace_count_after(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_count_after[i]:0;}
__attribute__((export_name("x86_get_x87_trace_status_before"))) uint32_t x86_get_x87_trace_status_before(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_status_before[i]:0;}
__attribute__((export_name("x86_get_x87_trace_status_after"))) uint32_t x86_get_x87_trace_status_after(uint32_t i){return i<X87_TRACE_DEPTH?x87_trace_status_after[i]:0;}
__attribute__((export_name("x86_get_x87_last_eip"))) uint32_t x86_get_x87_last_eip(void){return x87_last_eip;}
__attribute__((export_name("x86_get_x87_last_opcode"))) uint32_t x86_get_x87_last_opcode(void){return x87_last_opcode;}
__attribute__((export_name("x86_get_x87_last_modrm"))) uint32_t x86_get_x87_last_modrm(void){return x87_last_modrm;}
__attribute__((export_name("x86_get_x87_last_count_before"))) uint32_t x86_get_x87_last_count_before(void){return x87_last_count_before;}
__attribute__((export_name("x86_get_x87_last_count_after"))) uint32_t x86_get_x87_last_count_after(void){return x87_last_count_after;}
__attribute__((export_name("x86_get_x87_last_fault_eip"))) uint32_t x86_get_x87_last_fault_eip(void){return x87_last_fault_eip;}
__attribute__((export_name("x86_get_x87_last_fault_opcode"))) uint32_t x86_get_x87_last_fault_opcode(void){return x87_last_fault_opcode;}
__attribute__((export_name("x86_get_x87_last_fault_modrm"))) uint32_t x86_get_x87_last_fault_modrm(void){return x87_last_fault_modrm;}
__attribute__((export_name("x86_get_x87_last_fault_count"))) uint32_t x86_get_x87_last_fault_count(void){return x87_last_fault_count;}
__attribute__((export_name("x86_get_xmm_dword")))
uint32_t x86_get_xmm_dword(uint32_t reg,uint32_t lane){if(reg>=8u||lane>=4u)return 0xFFFFFFFFu;uint32_t p=lane*4u;return (uint32_t)xmm[reg][p]|((uint32_t)xmm[reg][p+1u]<<8)|((uint32_t)xmm[reg][p+2u]<<16)|((uint32_t)xmm[reg][p+3u]<<24);}
__attribute__((export_name("x86_get_memory_faults")))
uint32_t x86_get_memory_faults(void){return x86_mem_faults;}
__attribute__((export_name("x86_get_last_memory_fault_address")))
uint32_t x86_get_last_memory_fault_address(void){return x86_last_fault_address;}
__attribute__((export_name("x86_get_last_memory_fault_size")))
uint32_t x86_get_last_memory_fault_size(void){return x86_last_fault_size;}
__attribute__((export_name("x86_get_last_memory_fault_kind")))
uint32_t x86_get_last_memory_fault_kind(void){return x86_last_fault_kind;}
__attribute__((export_name("x86_get_current_imm32")))
uint32_t x86_get_current_imm32(void){
 if(!loaded||!x86_mem_region_find(eip+1u,4u,X86_MEM_READ))return 0xFFFFFFFFu;
 return rd32(eip+1u);
}
__attribute__((export_name("x86_get_last_indirect_slot"))) uint32_t x86_get_last_indirect_slot(void){return last_indirect_slot;}
__attribute__((export_name("x86_get_last_indirect_target"))) uint32_t x86_get_last_indirect_target(void){return last_indirect_target;}
__attribute__((export_name("x86_get_requested_image_base"))) uint32_t x86_get_requested_image_base(void){return requested_image_base;}
__attribute__((export_name("x86_get_image_base"))) uint32_t x86_get_image_base(void){return image_base;}
__attribute__((export_name("x86_get_image_size"))) uint32_t x86_get_image_size(void){return image_size;}
__attribute__((export_name("x86_get_relocation_rva"))) uint32_t x86_get_relocation_rva(void){return reloc_rva;}
__attribute__((export_name("x86_get_relocation_size"))) uint32_t x86_get_relocation_size(void){return reloc_size;}
__attribute__((export_name("x86_get_import_rva"))) uint32_t x86_get_import_rva(void){return import_rva;}
__attribute__((export_name("x86_get_import_size"))) uint32_t x86_get_import_size(void){return import_size;}
__attribute__((export_name("x86_get_relocation_needed"))) uint32_t x86_get_relocation_needed(void){return relocation_needed;}
__attribute__((export_name("x86_get_dll_count"))) uint32_t x86_get_dll_count(void){return dll_count;}
__attribute__((export_name("x86_get_import_count"))) uint32_t x86_get_import_count(void){return import_count;}
__attribute__((export_name("x86_get_import_resolved"))) uint32_t x86_get_import_resolved(void){return import_resolved;}
__attribute__((export_name("x86_get_import_failed"))) uint32_t x86_get_import_failed(void){return import_failed;}
__attribute__((export_name("x86_get_last_import_dll_rva"))) uint32_t x86_get_last_import_dll_rva(void){return last_import_dll;}
__attribute__((export_name("x86_get_last_import_func_rva"))) uint32_t x86_get_last_import_func_rva(void){return last_import_func;}
__attribute__((export_name("x86_get_last_import_thunk_rva"))) uint32_t x86_get_last_import_thunk_rva(void){return last_import_thunk;}
__attribute__((export_name("x86_get_last_import_target"))) uint32_t x86_get_last_import_target(void){return last_import_target;}
__attribute__((export_name("x86_get_last_failed_import_dll_rva"))) uint32_t x86_get_last_failed_import_dll_rva(void){return last_failed_import_dll;}
__attribute__((export_name("x86_get_last_failed_import_func_rva"))) uint32_t x86_get_last_failed_import_func_rva(void){return last_failed_import_func;}
__attribute__((export_name("x86_get_gdr_count"))) uint32_t x86_get_gdr_count(void){return x86_gdr_count;}
__attribute__((export_name("x86_get_gdr_dll_rva"))) uint32_t x86_get_gdr_dll_rva(uint32_t i){return i<x86_gdr_count?x86_gdr[i].dll_rva:0;}
__attribute__((export_name("x86_get_gdr_func_rva"))) uint32_t x86_get_gdr_func_rva(uint32_t i){return i<x86_gdr_count?x86_gdr[i].func_rva:0;}
__attribute__((export_name("x86_get_gdr_iat_rva"))) uint32_t x86_get_gdr_iat_rva(uint32_t i){return i<x86_gdr_count?x86_gdr[i].iat_rva:0;}
__attribute__((export_name("x86_get_gdr_target"))) uint32_t x86_get_gdr_target(uint32_t i){return i<x86_gdr_count?x86_gdr[i].target:0;}
__attribute__((export_name("x86_get_gdr_status"))) uint32_t x86_get_gdr_status(uint32_t i){return i<x86_gdr_count?x86_gdr[i].status:0xFFFFFFFFu;}
__attribute__((export_name("x86_get_gdr_call_count"))) uint32_t x86_get_gdr_call_count(uint32_t i){return i<x86_gdr_count?x86_gdr[i].call_count:0;}
__attribute__((export_name("x86_xapi_scratch"))) uint32_t x86_xapi_scratch(void){return (uint32_t)(uintptr_t)xapi_scratch;}
__attribute__((export_name("x86_xapi_slots"))) uint32_t x86_xapi_slots(void){return (uint32_t)(uintptr_t)xapi_slots;}
__attribute__((export_name("x86_xapi_reset"))) void x86_xapi_reset(void){xapi_count=0;xapi_pool_used=0;xapi_alias_count=0;xapi_duplicate_count=0;xapi_last_idx=0xFFFFFFFFu;}
/* scratch layout: "lib\0name\0" then nargs type-code bytes. Returns index, or 0xFFFFFFFF on error. */
__attribute__((export_name("x86_xapi_register"))) uint32_t x86_xapi_register(uint32_t id,uint32_t abi,uint32_t nargs,uint32_t ret){
 if(xapi_count>=XAPI_MAX_FUNCS||nargs>16u)return 0xFFFFFFFFu;
 uint32_t ll=xapi_len(xapi_scratch,200u),nl2=xapi_len(xapi_scratch+ll+1u,200u);
 for(uint32_t i=0;i<xapi_count;i++){
  x86_xapi_fn_t*f=&xapi_fn[i];
  int same_name=xapi_cstreq(xapi_pool+f->lib_off,(const char*)xapi_scratch)&&
                xapi_cstreq(xapi_pool+f->name_off,(const char*)(xapi_scratch+ll+1u));
  int same_sig=same_name&&f->id==id&&f->abi==(uint8_t)abi&&f->nargs==(uint8_t)nargs&&f->ret==(uint8_t)ret;
  if(same_sig){
   for(uint32_t k=0;k<nargs;k++)if(f->args[k]!=xapi_scratch[ll+nl2+2u+k]){same_sig=0;break;}
   if(same_sig){xapi_duplicate_count++;return i;}
  }
  if(f->id==id||same_name)return 0xFFFFFFFFu;
 }
 uint32_t lo=xapi_pool_add(xapi_scratch,ll),no=xapi_pool_add(xapi_scratch+ll+1u,nl2);
 if(lo==0xFFFFFFFFu||no==0xFFFFFFFFu)return 0xFFFFFFFFu;
 x86_xapi_fn_t*f=&xapi_fn[xapi_count];
 f->id=id;f->lib_off=lo;f->name_off=no;f->calls=0;f->abi=(uint8_t)abi;f->nargs=(uint8_t)nargs;f->ret=(uint8_t)ret;
 for(uint32_t i=0;i<nargs;i++)f->args[i]=xapi_scratch[ll+nl2+2u+i];
 return xapi_count++;
}
/* scratch layout: "alias.dll\0target.dll\0" */
__attribute__((export_name("x86_xapi_register_alias"))) uint32_t x86_xapi_register_alias(void){
 if(xapi_alias_count>=XAPI_MAX_ALIASES)return 0xFFFFFFFFu;
 uint32_t al=xapi_len(xapi_scratch,200u),tl=xapi_len(xapi_scratch+al+1u,200u);
 uint32_t a=xapi_pool_add(xapi_scratch,al),t=xapi_pool_add(xapi_scratch+al+1u,tl);
 if(a==0xFFFFFFFFu||t==0xFFFFFFFFu)return 0xFFFFFFFFu;
 xapi_alias_from[xapi_alias_count]=a;xapi_alias_to[xapi_alias_count]=t;return xapi_alias_count++;
}
__attribute__((export_name("x86_get_xapi_count"))) uint32_t x86_get_xapi_count(void){return xapi_count;}
__attribute__((export_name("x86_get_xapi_duplicate_count"))) uint32_t x86_get_xapi_duplicate_count(void){return xapi_duplicate_count;}
__attribute__((export_name("x86_get_xapi_id"))) uint32_t x86_get_xapi_id(uint32_t i){return i<xapi_count?xapi_fn[i].id:0;}
/* Describe registered function i for the shell: writes "lib\0name\0" into the xapi scratch
 * buffer and returns nargs | ret<<8 | abi<<16, or 0xFFFFFFFF when i is out of range. */
__attribute__((export_name("x86_xapi_describe"))) uint32_t x86_xapi_describe(uint32_t i){
 if(i>=xapi_count)return 0xFFFFFFFFu;
 const x86_xapi_fn_t*f=&xapi_fn[i];uint32_t o=0;
 for(const char*c=xapi_pool+f->lib_off;*c&&o<250u;c++)xapi_scratch[o++]=(uint8_t)*c;
 xapi_scratch[o++]=0;
 for(const char*c=xapi_pool+f->name_off;*c&&o<500u;c++)xapi_scratch[o++]=(uint8_t)*c;
 xapi_scratch[o++]=0;
 return (uint32_t)f->nargs|((uint32_t)f->ret<<8)|((uint32_t)f->abi<<16);
}
__attribute__((export_name("x86_get_xapi_call_count"))) uint32_t x86_get_xapi_call_count(uint32_t i){return i<xapi_count?xapi_fn[i].calls:0;}
__attribute__((export_name("x86_get_last_xapi_id"))) uint32_t x86_get_last_xapi_id(void){return xapi_last_id;}
__attribute__((export_name("x86_guest_read8"))) uint32_t x86_guest_read8(uint32_t a){return MEM8(a);}
__attribute__((export_name("x86_guest_write8"))) void x86_guest_write8(uint32_t a,uint32_t v){MEM8(a)=(uint8_t)v;}
__attribute__((export_name("x86_guest_read32"))) uint32_t x86_guest_read32(uint32_t a){return rd32(a);}
__attribute__((export_name("x86_guest_write32"))) void x86_guest_write32(uint32_t a,uint32_t v){wr32(a,v);}
__attribute__((export_name("x86_get_last_unresolved_gdr"))) uint32_t x86_get_last_unresolved_gdr(void){return last_unresolved_gdr;}
__attribute__((export_name("x86_get_gdr_dll_name_byte"))) uint32_t x86_get_gdr_dll_name_byte(uint32_t i,uint32_t j){return (i<x86_gdr_count&&j<255u)?MEM8(image_base+x86_gdr[i].dll_rva+j):0;}
__attribute__((export_name("x86_get_gdr_func_name_byte"))) uint32_t x86_get_gdr_func_name_byte(uint32_t i,uint32_t j){return (i<x86_gdr_count&&j<255u)?MEM8(image_base+x86_gdr[i].func_rva+2u+j):0;}
__attribute__((export_name("x86_alloc"))) uint32_t x86_alloc(uint32_t n){return guest_alloc_raw(n);}
/* Like x86_alloc, but the block is a registered readable/writable guest memory region, which
 * x86_dll_register_image and the x86_fs_* mount calls require for their source buffers. */
__attribute__((export_name("x86_alloc_region"))) uint32_t x86_alloc_region(uint32_t n){return x86_mem_alloc_region(n,X86_MEM_READ|X86_MEM_WRITE,9u);}
__attribute__((export_name("x86_crt_malloc"))) uint32_t x86_crt_malloc(uint32_t size){return x86_crt_malloc_impl(size);}
__attribute__((export_name("x86_crt_calloc"))) uint32_t x86_crt_calloc(uint32_t count,uint32_t size){return x86_crt_calloc_impl(count,size);}
__attribute__((export_name("x86_crt_free"))) uint32_t x86_crt_free(uint32_t address){return x86_crt_free_impl(address);}
__attribute__((export_name("x86_crt_realloc"))) uint32_t x86_crt_realloc(uint32_t address,uint32_t size){return x86_crt_realloc_impl(address,size);}
__attribute__((export_name("x86_crt_memcpy"))) uint32_t x86_crt_memcpy(uint32_t dst,uint32_t src,uint32_t size){
 if(!x86_mem_region_find(src,size,X86_MEM_READ)||!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_mem_faults++;return 0;}
 for(uint32_t i=0;i<size;i++)wr8(dst+i,MEM8(src+i)); return dst;
}
__attribute__((export_name("x86_crt_memmove"))) uint32_t x86_crt_memmove(uint32_t dst,uint32_t src,uint32_t size){
 if(!x86_mem_region_find(src,size,X86_MEM_READ)||!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_mem_faults++;return 0;}
 if(dst==src||size==0)return dst;
 if(dst<src){for(uint32_t i=0;i<size;i++)wr8(dst+i,MEM8(src+i));}
 else{for(uint32_t i=size;i>0;i--)wr8(dst+i-1u,MEM8(src+i-1u));}
 return dst;
}
__attribute__((export_name("x86_crt_memset"))) uint32_t x86_crt_memset(uint32_t dst,uint32_t value,uint32_t size){
 if(!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_mem_faults++;return 0;}
 for(uint32_t i=0;i<size;i++)wr8(dst+i,(uint8_t)value); return dst;
}
__attribute__((export_name("x86_crt_memcmp"))) int32_t x86_crt_memcmp(uint32_t a,uint32_t b,uint32_t size){
 if(!x86_mem_region_find(a,size,X86_MEM_READ)||!x86_mem_region_find(b,size,X86_MEM_READ)){x86_mem_faults++;return 0;}
 for(uint32_t i=0;i<size;i++){uint8_t x=MEM8(a+i),y=MEM8(b+i);if(x!=y)return x<y?-1:1;} return 0;
}
__attribute__((export_name("x86_crt_strlen"))) uint32_t x86_crt_strlen(uint32_t s){
 uint32_t n=0;
 while(n<0xFFFFFFFFu){
  if(!x86_mem_region_find(s+n,1u,X86_MEM_READ)){x86_mem_faults++;return 0;}
  if(MEM8(s+n)==0)return n; n++;
 }
 x86_mem_faults++; return 0;
}
__attribute__((export_name("x86_crt_strcpy"))) uint32_t x86_crt_strcpy(uint32_t dst,uint32_t src){
 uint32_t n=x86_crt_strlen(src); if(!n&&(!x86_mem_region_find(src,1u,X86_MEM_READ)||MEM8(src)!=0))return 0;
 if(!x86_mem_region_find(dst,n+1u,X86_MEM_WRITE)){x86_mem_faults++;return 0;}
 for(uint32_t i=0;i<=n;i++)wr8(dst+i,MEM8(src+i)); return dst;
}
__attribute__((export_name("x86_crt_strcmp"))) int32_t x86_crt_strcmp(uint32_t a,uint32_t b){
 uint32_t i=0;
 for(;;i++){
  if(!x86_mem_region_find(a+i,1u,X86_MEM_READ)||!x86_mem_region_find(b+i,1u,X86_MEM_READ)){x86_mem_faults++;return 0;}
  uint8_t x=MEM8(a+i),y=MEM8(b+i); if(x!=y)return x<y?-1:1; if(x==0)return 0;
 }
}
__attribute__((export_name("x86_get_guest_heap"))) uint32_t x86_get_guest_heap(void){return guest_heap;}
__attribute__((export_name("x86_virtual_alloc"))) uint32_t x86_virtual_alloc(uint32_t size){return x86_mem_alloc_region(size,X86_MEM_READ|X86_MEM_WRITE,2u);}
__attribute__((export_name("x86_virtual_free"))) uint32_t x86_virtual_free(uint32_t address){return x86_mem_free_region(address);}
__attribute__((export_name("x86_mem_validate"))) uint32_t x86_mem_validate(uint32_t address,uint32_t size,uint32_t flags){uint32_t need=flags&(X86_MEM_READ|X86_MEM_WRITE|X86_MEM_EXEC);if(!x86_mem_region_find(address,size,need)){x86_mem_faults++;return 0;}return 1;}
__attribute__((export_name("x86_mem_copy"))) uint32_t x86_mem_copy(uint32_t dst,uint32_t src,uint32_t size){if(!x86_mem_region_find(src,size,X86_MEM_READ)||!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_mem_faults++;return 0;}copy_bytes(dst,src,size);return 1;}
__attribute__((export_name("x86_mem_set"))) uint32_t x86_mem_set(uint32_t dst,uint32_t value,uint32_t size){if(!x86_mem_region_find(dst,size,X86_MEM_WRITE)){x86_mem_faults++;return 0;}for(uint32_t i=0;i<size;i++)wr8(dst+i,(uint8_t)value);return 1;}
__attribute__((export_name("x86_get_memory_region_count"))) uint32_t x86_get_memory_region_count(void){return x86_mem_region_count;}
__attribute__((export_name("x86_get_virtual_heap"))) uint32_t x86_get_virtual_heap(void){return guest_vm;}
__attribute__((export_name("x86_get_last_virtual_alloc"))) uint32_t x86_get_last_virtual_alloc(void){return last_virtual_alloc;}
__attribute__((export_name("x86_get_last_virtual_alloc_size"))) uint32_t x86_get_last_virtual_alloc_size(void){return last_virtual_alloc_size;}
__attribute__((export_name("x86_get_virtual_free_count"))) uint32_t x86_get_virtual_free_count(void){return virtual_free_count;}
__attribute__((export_name("x86_fs_mount_file"))) uint32_t x86_fs_mount_file(uint32_t path_ptr,uint32_t data_ptr,uint32_t size){
 char raw[X86_FS_MAX_PATH];if(!x86_fs_guest_string(path_ptr,raw,sizeof(raw)))return 0;return x86_fs_mount_impl(raw,data_ptr,size);
}
__attribute__((export_name("x86_fs_open"))) uint32_t x86_fs_open(uint32_t path_ptr,uint32_t access,uint32_t flags){
 char raw[X86_FS_MAX_PATH];if(!x86_fs_guest_string(path_ptr,raw,sizeof(raw)))return 0;return x86_fs_open_impl(raw,access,flags);
}
__attribute__((export_name("x86_fs_close"))) uint32_t x86_fs_close(uint32_t handle){return x86_fs_close_impl(handle);}
__attribute__((export_name("x86_fs_read"))) uint32_t x86_fs_read(uint32_t handle,uint32_t dst,uint32_t size){uint32_t n=0;uint32_t ok=x86_fs_read_impl(handle,dst,size,&n);return ok?n:0xFFFFFFFFu;}
__attribute__((export_name("x86_fs_write"))) uint32_t x86_fs_write(uint32_t handle,uint32_t src,uint32_t size){uint32_t n=0;uint32_t ok=x86_fs_write_impl(handle,src,size,&n);return ok?n:0xFFFFFFFFu;}
__attribute__((export_name("x86_fs_seek"))) uint32_t x86_fs_seek(uint32_t handle,int32_t distance,uint32_t origin){return x86_fs_seek_impl(handle,distance,origin);}
__attribute__((export_name("x86_fs_size"))) uint32_t x86_fs_size(uint32_t handle){return x86_fs_size_impl(handle);}
__attribute__((export_name("x86_fs_exists"))) uint32_t x86_fs_exists(uint32_t path_ptr){char raw[X86_FS_MAX_PATH];if(!x86_fs_guest_string(path_ptr,raw,sizeof(raw)))return 0;return x86_fs_exists_impl(raw);}
__attribute__((export_name("x86_fs_get_last_error"))) uint32_t x86_fs_get_last_error(void){return x86_fs_last_error;}
__attribute__((export_name("x86_reg_open_key"))) uint32_t x86_reg_open_key(uint32_t parent,uint32_t sub_ptr,uint32_t out_handle_ptr){
 char raw[X86_REG_MAX_PATH];uint32_t handle=0;if(sub_ptr&&!x86_fs_guest_string(sub_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;uint32_t result=x86_reg_open_impl(parent,sub_ptr?raw:"",&handle);if(result==X86_REG_ERROR_SUCCESS&&out_handle_ptr&&x86_mem_region_find(out_handle_ptr,4u,X86_MEM_WRITE))wr32(out_handle_ptr,handle);return result;
}
__attribute__((export_name("x86_reg_create_key"))) uint32_t x86_reg_create_key(uint32_t parent,uint32_t sub_ptr,uint32_t out_handle_ptr){
 char raw[X86_REG_MAX_PATH];uint32_t handle=0,disp=0;if(sub_ptr&&!x86_fs_guest_string(sub_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;uint32_t result=x86_reg_create_impl(parent,sub_ptr?raw:"",&handle,&disp);if(result==X86_REG_ERROR_SUCCESS&&out_handle_ptr&&x86_mem_region_find(out_handle_ptr,4u,X86_MEM_WRITE))wr32(out_handle_ptr,handle);return result;
}
__attribute__((export_name("x86_reg_close_key"))) uint32_t x86_reg_close_key(uint32_t handle){return x86_reg_close_impl(handle);}
__attribute__((export_name("x86_reg_query_value"))) uint32_t x86_reg_query_value(uint32_t handle,uint32_t name_ptr,uint32_t type_ptr,uint32_t data_ptr,uint32_t size_ptr){
 char raw[X86_REG_MAX_VALUE_NAME];uint32_t type=0,size=0,result;if(name_ptr&&!x86_fs_guest_string(name_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;if(!size_ptr||!x86_mem_region_find(size_ptr,4u,X86_MEM_READ|X86_MEM_WRITE))return X86_REG_ERROR_INVALID_PARAMETER;size=rd32(size_ptr);result=x86_reg_query_value_impl(handle,name_ptr?raw:"",&type,data_ptr?((uint8_t*)(uintptr_t)data_ptr):0,&size);if(type_ptr&&x86_mem_region_find(type_ptr,4u,X86_MEM_WRITE))wr32(type_ptr,type);if(x86_mem_region_find(size_ptr,4u,X86_MEM_WRITE))wr32(size_ptr,size);return result;
}
__attribute__((export_name("x86_reg_set_value"))) uint32_t x86_reg_set_value(uint32_t handle,uint32_t name_ptr,uint32_t type,uint32_t data_ptr,uint32_t size){
 char raw[X86_REG_MAX_VALUE_NAME];if(name_ptr&&!x86_fs_guest_string(name_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;if(size&&!x86_mem_region_find(data_ptr,size,X86_MEM_READ))return X86_REG_ERROR_INVALID_PARAMETER;uint8_t tmp[X86_REG_MAX_VALUE_DATA];if(size>sizeof(tmp))return X86_REG_ERROR_INVALID_PARAMETER;for(uint32_t i=0;i<size;i++)tmp[i]=MEM8(data_ptr+i);return x86_reg_set_value_impl(handle,name_ptr?raw:"",type,tmp,size);
}
__attribute__((export_name("x86_reg_delete_value"))) uint32_t x86_reg_delete_value(uint32_t handle,uint32_t name_ptr){char raw[X86_REG_MAX_VALUE_NAME];if(name_ptr&&!x86_fs_guest_string(name_ptr,raw,sizeof(raw)))return X86_REG_ERROR_INVALID_PARAMETER;return x86_reg_delete_value_impl(handle,name_ptr?raw:"");}
__attribute__((export_name("x86_reg_key_exists"))) uint32_t x86_reg_key_exists(uint32_t parent,uint32_t sub_ptr){char raw[X86_REG_MAX_PATH];if(sub_ptr&&!x86_fs_guest_string(sub_ptr,raw,sizeof(raw)))return 0;return x86_reg_key_exists_impl(parent,sub_ptr?raw:"");}
__attribute__((export_name("x86_reg_value_exists"))) uint32_t x86_reg_value_exists(uint32_t handle,uint32_t name_ptr){char raw[X86_REG_MAX_VALUE_NAME];if(name_ptr&&!x86_fs_guest_string(name_ptr,raw,sizeof(raw)))return 0;return x86_reg_value_exists_impl(handle,name_ptr?raw:"");}
__attribute__((export_name("x86_reg_get_last_error"))) uint32_t x86_reg_get_last_error(void){return x86_reg_last_error;}
__attribute__((export_name("x86_get_loaded"))) uint32_t x86_get_loaded(void){return loaded;}
__attribute__((export_name("x86_get_load_error"))) uint32_t x86_get_load_error(void){return load_error;}
__attribute__((export_name("x86_get_load_ptr"))) uint32_t x86_get_load_ptr(void){return last_load_ptr;}
__attribute__((export_name("x86_get_load_size"))) uint32_t x86_get_load_size(void){return last_load_size;}
__attribute__((export_name("x86_get_message_count"))) uint32_t x86_get_message_count(void){return message_count;}
__attribute__((export_name("x86_get_last_message"))) uint32_t x86_get_last_message(void){return message_last;}
__attribute__((export_name("x86_get_message_quit"))) uint32_t x86_get_message_quit(void){return message_quit;}
__attribute__((export_name("x86_get_mouse_clicks"))) uint32_t x86_get_mouse_clicks(void){return mouse_clicks;}
__attribute__((export_name("x86_get_mouse_right_clicks"))) uint32_t x86_get_mouse_right_clicks(void){return mouse_right_clicks;}
__attribute__((export_name("x86_get_mouse_middle_clicks"))) uint32_t x86_get_mouse_middle_clicks(void){return mouse_middle_clicks;}
__attribute__((export_name("x86_get_mouse_moves"))) uint32_t x86_get_mouse_moves(void){return mouse_moves;}
__attribute__((export_name("x86_get_surface_width"))) uint32_t x86_get_surface_width(void){return surface_width;}
__attribute__((export_name("x86_get_surface_height"))) uint32_t x86_get_surface_height(void){return surface_height;}
__attribute__((export_name("x86_get_rich_ops_pass"))) uint32_t x86_get_rich_ops_pass(void){return regs[R_EBP]==0x584F5053u?1u:0u;}
__attribute__((export_name("x86_get_legacy_execution_count"))) uint32_t x86_get_legacy_execution_count(void){return legacy_execution_count;}
__attribute__((export_name("x86_get_stress_report_word"))) uint32_t x86_get_stress_report_word(uint32_t index){if(index>=16u)return 0;return rd32(X86_STRESS_REPORT_BASE+(index*4u));}
static uint32_t x86_crt_invoke_callback_impl(uint32_t target,uint32_t *ok_out){
 if(ok_out)*ok_out=0;
 if(!loaded||!x86_mem_region_find(target,1u,X86_MEM_EXEC))return 0;
 uint32_t saved_regs[8],saved_eflags=eflags,saved_eip=eip,saved_halted=halted,saved_error=cpu_error,saved_steps=steps;
 for(uint32_t i=0;i<8;i++)saved_regs[i]=regs[i];
 halted=0;cpu_error=0;
 if(!x86_stack_push32(X86_CRT_CALLBACK_MARKER)||!x86_stack_push32(X86_CRT_CALLBACK_SENTINEL)){
  for(uint32_t i=0;i<8;i++)regs[i]=saved_regs[i];eflags=saved_eflags;eip=saved_eip;halted=saved_halted;cpu_error=saved_error;steps=saved_steps;return 0;
 }
 eip=target;
 uint32_t result=0,ok=0;
 for(uint32_t i=0;i<10000u;i++){
  if(eip==X86_CRT_CALLBACK_SENTINEL){result=regs[R_EAX];ok=1;break;}
  if(halted||cpu_error)break;
  if(cpu_step()<0)break;
 }
 for(uint32_t i=0;i<8;i++)regs[i]=saved_regs[i];
 eflags=saved_eflags;eip=saved_eip;halted=saved_halted;cpu_error=saved_error;steps=saved_steps;
 if(ok&&ok_out)*ok_out=1;
 return ok?result:0;
}
__attribute__((export_name("x86_crt_startup"))) uint32_t x86_crt_startup(void){
 crt_errno=0;crt_last_error=0;crt_started=1;crt_exited=0;crt_exit_code=0;
 crt_last_termination_kind=0u;crt_last_termination_caller=0u;crt_last_termination_return_eip=0u;
 crt_last_termination_target=0u;crt_last_termination_arg0=0u;
 crt_last_shim_index=0xFFFFFFFFu;crt_last_shim_caller=0u;crt_last_shim_target=0u;crt_last_shim_arg0=0u;crt_last_shim_argc=0u;crash_hit=0u;crash_return_eip=0u;crash_nframes=0u;crash_arg0=0u;
 crt_atexit_count=0;crt_last_atexit_result=0;crt_last_atexit_ok=0;crt_atexit_running=0;return 1;
}
__attribute__((export_name("x86_crt_get_errno"))) int32_t x86_crt_get_errno(void){return crt_errno;}
__attribute__((export_name("x86_crt_set_errno"))) int32_t x86_crt_set_errno(int32_t value){crt_errno=value;return value;}
__attribute__((export_name("x86_crt_get_last_error"))) uint32_t x86_crt_get_last_error(void){return crt_last_error;}
__attribute__((export_name("x86_crt_set_last_error"))) uint32_t x86_crt_set_last_error(uint32_t value){crt_last_error=value;return value;}
__attribute__((export_name("x86_crt_get_started"))) uint32_t x86_crt_get_started(void){return crt_started;}
__attribute__((export_name("x86_crt_get_exited"))) uint32_t x86_crt_get_exited(void){return crt_exited;}
__attribute__((export_name("x86_crt_get_exit_code"))) uint32_t x86_crt_get_exit_code(void){return crt_exit_code;}
__attribute__((export_name("x86_crt_get_last_termination_kind"))) uint32_t x86_crt_get_last_termination_kind(void){return crt_last_termination_kind;}
__attribute__((export_name("x86_crt_get_last_termination_caller"))) uint32_t x86_crt_get_last_termination_caller(void){return crt_last_termination_caller;}
__attribute__((export_name("x86_crt_get_last_termination_return_eip"))) uint32_t x86_crt_get_last_termination_return_eip(void){return crt_last_termination_return_eip;}
__attribute__((export_name("x86_crt_get_last_termination_target"))) uint32_t x86_crt_get_last_termination_target(void){return crt_last_termination_target;}
__attribute__((export_name("x86_crt_get_last_termination_arg0"))) uint32_t x86_crt_get_last_termination_arg0(void){return crt_last_termination_arg0;}
__attribute__((export_name("x86_crt_get_last_shim_index"))) uint32_t x86_crt_get_last_shim_index(void){return crt_last_shim_index;}
__attribute__((export_name("x86_crt_get_last_shim_caller"))) uint32_t x86_crt_get_last_shim_caller(void){return crt_last_shim_caller;}
__attribute__((export_name("x86_crt_get_last_shim_target"))) uint32_t x86_crt_get_last_shim_target(void){return crt_last_shim_target;}
__attribute__((export_name("x86_crt_get_last_shim_arg0"))) uint32_t x86_crt_get_last_shim_arg0(void){return crt_last_shim_arg0;}
__attribute__((export_name("x86_crt_get_last_shim_argc"))) uint32_t x86_crt_get_last_shim_argc(void){return crt_last_shim_argc;}
__attribute__((export_name("x86_crt_atexit"))) uint32_t x86_crt_atexit(uint32_t callback){
 if(!callback||crt_exited||crt_atexit_running){crt_errno=X86_CRT_EINVAL;return 0;}
 if(crt_atexit_count>=X86_CRT_ATEXIT_MAX){crt_errno=X86_CRT_ENOMEM;return 0;}
 crt_atexit_callbacks[crt_atexit_count++]=callback;return 1;
}
__attribute__((export_name("x86_crt_get_atexit_count"))) uint32_t x86_crt_get_atexit_count(void){return crt_atexit_count;}
__attribute__((export_name("x86_crt_get_atexit_callback"))) uint32_t x86_crt_get_atexit_callback(uint32_t index){return index<crt_atexit_count?crt_atexit_callbacks[index]:0;}
__attribute__((export_name("x86_crt_run_atexit"))) uint32_t x86_crt_run_atexit(void){
 if(crt_atexit_running)return 0;
 crt_atexit_running=1;uint32_t ran=0,failed=0;
 while(crt_atexit_count){
  uint32_t callback=crt_atexit_callbacks[--crt_atexit_count];
  uint32_t callback_ok=0,result=x86_crt_invoke_callback_impl(callback,&callback_ok);
  crt_last_atexit_result=result;crt_last_atexit_ok=callback_ok;
  if(!callback_ok)failed=1;else ran++;
 }
 crt_atexit_running=0;
 if(failed)crt_errno=X86_CRT_EFAULT;
 return failed?0:ran;
}
__attribute__((export_name("x86_crt_exit"))) uint32_t x86_crt_exit(uint32_t code){
 if(!crt_started)x86_crt_startup();
 if(crt_exited)return crt_exit_code==code?1u:0u;
 uint32_t ok=x86_crt_run_atexit();
 crt_exit_code=code;crt_exited=1;
 return ok;
}
__attribute__((export_name("x86_crt_get_last_atexit_result"))) uint32_t x86_crt_get_last_atexit_result(void){return crt_last_atexit_result;}
__attribute__((export_name("x86_crt_invoke_callback"))) uint32_t x86_crt_invoke_callback(uint32_t callback){return x86_crt_invoke_callback_impl(callback,0);}
__attribute__((export_name("x86_get_running"))) uint32_t x86_get_running(void){return loaded&&!halted&&!cpu_error;}
