#ifndef SLLVM_SANCUS_H
#define SLLVM_SANCUS_H

#include "llvm/IR/Module.h"
#include "llvm/SLLVM.h"

using namespace llvm;
using namespace sllvm;

namespace sllvm {
  namespace sancus {

    constexpr const unsigned R6_PRet = 0xffff; // Return from call to pm
    constexpr const unsigned R6_URet = 0xfffe; // Return from call to non-pm
    constexpr const char *global_pc = "sllvm_pc"; // TODO: Remove

    inline const std::string getFixDataSectionFlagName() {
      return (Twine(prefix) + "-fix-data-section").str();
    }

    inline const std::string getGLobalStackName() {
      return (Twine(prefix) + "_r1").str();
    }

    inline const std::string getDispatcherAliasName(const Function *F) {
      assert(isEEntry(F));
      return (Twine(prefix) + "_" + F->getName()).str();
    }

    inline const std::string getEntryPointIdentifierName(const Function *F) {
      assert(isEEntry(F));
      return (Twine(prefix) + "_id_" + F->getName()).str();
    }

    template<typename T>
    inline const std::string getDispatcherName(const T V) {
      return (Twine(prefix) + "_dispatch_" + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getOCallHandlerName(const T V) {
      return (Twine(prefix) + "_excall_" + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getAttestName(const T V) {
      return (Twine(prefix) + "_attest_" + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getLocalName(const T V, const char *N) {
      return (Twine(prefix) + "_" + getProtectionDomain(V) + "_l" +
          Twine(N)).str();
    }

    template<typename T>
    inline const std::string getLocalStackName(const T V) {
      return getLocalName(V, "stack");
    }

    template<typename T>
    inline const std::string getLocalR1AddrName(const T V) {
      return getLocalName(V, "r1_addr");
    }

    template<typename T>
    inline const std::string getLocalR1Name(const T V) {
      return getLocalName(V, "r1");
    }

    template<typename T>
    inline const std::string getLocalR4Name(const T V) {
      return getLocalName(V, "r4");
    }

    template<typename T>
    inline const std::string getLocalR5Name(const T V) {
      return getLocalName(V, "r5");
    }

    template<typename T>
    inline const std::string getLocalR8Name(const T V) {
      return getLocalName(V, "r8");
    }

    template<typename T>
    inline const std::string getLocalR9Name(const T V) {
      return getLocalName(V, "r9");
    }

    template<typename T>
    inline const std::string getLocalR10Name(const T V) {
      return getLocalName(V, "r10");
    }

    template<typename T>
    inline const std::string getLocalR11Name(const T V) {
      return getLocalName(V, "r11");
    }

    template<typename T>
    inline const std::string getStartOfTextSectionName(const T V) {
      return (Twine(prefix) + "_pm_" + getProtectionDomain(V) +
           "_text_start").str();
    }

    template<typename T>
    inline const std::string getEndOfTextSectionName(const T V) {
      return
          (Twine(prefix) + "_pm_" + getProtectionDomain(V) + "_text_end").str();
    }

    template<typename T>
    inline const std::string getStartOfDataSectionName(const T V) {
      return (Twine(prefix) + "_pm_" + getProtectionDomain(V) +
           "_data_start").str();
    }

    template<typename T>
    inline const std::string getEndOfDataSectionName(const T V) {
      return
          (Twine(prefix) + "_pm_" + getProtectionDomain(V) + "_data_end").str();
    }

    template<typename T>
    inline const std::string getTagName(const T V) {
      return (Twine(prefix) + "_tag_" + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getNonceName(const T V) {
      return (Twine(prefix) + "_nonce_" + getProtectionDomain(V)).str();
    }

    inline const std::string getSecureLinkingIdName(const Function *Caller,
        const Function * Callee) {
      // TODO: Forbid the simple SLLVM programming model and XCU-PMs?
      // Now, it is necessary to use Callee->getName() instead of 
      //  getProtectionDomain(Callee) to be able to support the programming
      //  model from the master's thesis "Security Enhanced LLVM" combined
      //  with cross-compilation unit protected modules because the name of
      //  the protection domain of the called function is not always known
      //  in this case.
      return (Twine(prefix) + "_slid_" + getProtectionDomain(Caller) + "_"
          + Callee->getName()).str();
    }

    inline const std::string getSecureLinkingHashName(const Function *Caller,
        const Function * Callee) {
      // TODO: Forbid the simple SLLVM programming model and XCU-PMs?
      // Now, it is necessary to use Callee->getName() instead of 
      //  getProtectionDomain(Callee) to be able to support the programming
      //  model from the master's thesis "Security Enhanced LLVM" combined
      //  with cross-compilation unit protected modules because the name of
      //  the protection domain of the called function is not always known
      //  in this case.
      return (Twine(prefix) + "_hash_" + getProtectionDomain(Caller) + "_"
          + Callee->getName()).str();
    }

    inline const std::string getSecureLinkingSectionName(
        const Function *Caller, const Function * Callee) {
      return (Twine('.') + prefix + ".slink." + getProtectionDomain(Caller) + 
          "." + getProtectionDomain(Callee)).str();
    }

    template<typename T>
    inline const std::string getDataSectionName(const T V) {
      return (Twine('.') + prefix + ".data." + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getTextSectionName(const T V) {
      return (Twine('.') + prefix + ".text." + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getWrapSectionName(const T V) {
      return (Twine('.') + prefix + ".wrap." + getProtectionDomain(V)).str();
    }

    template<typename T>
    inline const std::string getDispatchSectionName(const T V) {
      return (Twine('.') + prefix + ".text.dispatch." +
           getProtectionDomain(V)).str();
    }
    
    template<typename T>
    inline const std::string getLocalR1AddrSectionName(const T V) {
      return (Twine('.') + prefix + ".data.lr1addr." +
           getProtectionDomain(V)).str();
    }

    inline bool hasFixedDataSection(const Module *M) {
      return M->getModuleFlag(getFixDataSectionFlagName()) != nullptr;
    }

    inline bool hasStack(const Module *M) {
      return !hasFixedDataSection(M);
    }

    constexpr const char *asm_eenter = R"(
  .p2align  1
  .type sllvm_eenter,@function
sllvm_eenter:
  ret
  )";

    constexpr const char *asm_eexit = R"(
  .p2align  1
  .type sllvm_eexit,@function
sllvm_eexit:
  ; Clear the status bits
  and #0x7ef8, r2
  ; This might be a return-to-enclave
  mov #0xffff, r6
  ret
  )";

    constexpr const char *asm_excall = R"(
  .p2align  1
  .type sllvm_excall,@function
  .globl sllvm_excall_<pm>
  .equiv sllvm_excall_<pm>, sllvm_excall
sllvm_excall:
  ; Save callee save Registers
  mov r4, &sllvm_<pm>_lr4
  mov r5, &sllvm_<pm>_lr5
  mov r9, &sllvm_<pm>_lr9
  mov r10, &sllvm_<pm>_lr10
  mov r11, &sllvm_<pm>_lr11
  ; Clear callee save Registers
  clr r4
  clr r5
  clr r9
  clr r10
  clr r11
  ; Clear the status bits
  and #0x7ef8, r2
  br r8
  )";

    constexpr const char *asm_ereturn = R"(
  .p2align  1
  .type sllvm_ereturn,@function
sllvm_ereturn:
  ; Restore callee save Registers
  mov &sllvm_<pm>_lr4, r4,
  mov &sllvm_<pm>_lr5, r5,
  mov &sllvm_<pm>_lr8, r8,
  mov &sllvm_<pm>_lr9, r9,
  mov &sllvm_<pm>_lr10, r10
  mov &sllvm_<pm>_lr11, r11
  ret
  )";

#if 0
    // TODO: Paramterize (Module, tag, nonce, vendor_id)
    // TODO: Have symbol names generated (sllvm_data_*, sllvm_text_*)
    constexpr const char* asm_protect = R"(
  .globl  sllvm_protect
  .p2align  1
  .type sllvm_protect,@function
sllvm_protect:
  mov #0, r9    ; tag
  mov #0, r10   ; nonce
  mov #1234, r11   ; vendor id
  mov #sllvm_text_section_start,  r12
  mov #sllvm_text_section_end,  r13
  mov #sllvm_data_section_start,  r14
  mov #sllvm_data_section_end,  r15
  .word 0x1381
  mov r15, r12
  ret
  )";
#endif

    constexpr const char *asm_attest = R"(
  .p2align  1
  .type sllvm_attest,@function
  .globl sllvm_attest_<pm>
  .equiv sllvm_attest_<pm>, sllvm_attest
sllvm_attest:
  mov 0(r13), r12
  cmp #0x0000, r12
  jeq .Ltag

  ; we have a stored ID, check if it  matches with the SM
  mov r14, r15
  .word 0x1386
  cmp r12, r15
  jne .Lexit
  ret

.Ltag:
  ; we don't have an ID yet, calculate tag
  .word 0x1382
  cmp #0x0000, r15
  jeq .Lexit
  mov r15, 0(r13)
  ret

.Lexit:
  ; TODO: call #sllvm_excall
  ;  (is not a call anymore)
  mov &sllvm_r1, r1
  ; set CPUOFF bit in status register 
  bis #0x210, r2
  call #exit
  )";

    constexpr const char *asm_reti = R"(
  .p2align  1
  .type sllvm_reti,@function
sllvm_reti:
  bic #1, &sllvm_<pm>_lr1
  mov &sllvm_<pm>_lr1, r1
  pop r4
  pop r5
  pop r6
  pop r7
  pop r8
  pop r9
  pop r10
  pop r11
  pop r12
  pop r13
  pop r14
  pop r15
  reti
  )";

    // TODO: Improve RTL internalization by actually hardening the
    //       compiler-rt functions
    constexpr const char *asm_mpyi = R"(
  .section .sllvm.text.<pm>.__mspabi_mpyi_<pm>,"ax",@progbits
  .globl __mspabi_mpyi_<pm>
  .p2align 1
  .type __mspabi_mpyi_<pm>,@function
  .equiv _nds___mspabi_mpyi, __mspabi_mpyi_<pm>
  .equiv _ndd___mspabi_mpyi, __mspabi_mpyi_<pm>
__mspabi_mpyi_<pm>:
	CMP.W	#0, R13
  JGE	.MPYL2
	MOV.B	#0, R14
	SUB.W	R13, R14
	MOV.W	R14, R13
	MOV.B	#1, R11
  JMP .MPYL3
.MPYL3:
	MOV.B	#16, R15
	MOV.B	#0, R14
.MPYL6:
	BIT.W	#1, R13
  JEQ	.MPYL4
	ADD.W	R12, R14
	JMP .MPYL5
.MPYL5:
	ADD.W	R12, R12
	RRA.W	R13
	ADD.B	#-1, R15
	AND	#0xff, R15
	CMP.W	#0, R15
  JNE	.MPYL6
	CMP.W	#0, R11 
  JEQ	.MPYL1
	MOV.B	#0, R12
	SUB.W	R14, R12
	MOV.W	R12, R14
  JMP .MPYL7
.MPYL1:
	MOV.W R3, R3
	MOV.W R3, R3
	MOV.W R3, R3
  JMP .MPYL7
.MPYL7:
	MOV.W	R14, R12
	RET
.MPYL2:
	MOV.W R3, R3
	MOV.W R3, R3
	MOV.W R3, R3
	MOV.B	#0, R11
	JMP	.MPYL3
.MPYL4:
	MOV.B R3, R3
	JMP	.MPYL5
  )";

    constexpr const char *asm_divu = R"(
  .section .sllvm.text.<pm>.__mspabi_divu_<pm>,"ax",@progbits
  .globl __mspabi_divu_<pm>
  .p2align 1
  .type __mspabi_divu_<pm>,@function
__mspabi_divu_<pm>:
  clr.b r14   ;
  call  #udivmodhi4_<pm>
  ret     
  )";

    constexpr const char *asm_divumodhi4 = R"(
  .section .sllvm.text.<pm>.udivmodhi4_<pm>,"ax",@progbits
  .globl udivmodhi4_<pm>
  .p2align 1
  .type udivmodhi4_<pm>,@function
udivmodhi4_<pm>:
  mov.b #17,  r15 ;#0x0011
  mov.b #1, r11 ;r3 As==01
.SLLVM1:
  cmp r12,  r13 ;
  jnc $+18      ;abs 0x885e
  clr.b r15   ;
.SLLVM2:
  cmp #0, r11 ;r3 As==00
  jnz $+30      ;abs 0x8870
  cmp #0, r14 ;r3 As==00
  jz  $+4       ;abs 0x885a
  mov r12,  r15 ;
  mov r15,  r12 ;
  ret     
  add #-1,  r15 ;r3 As==11
  cmp #0, r15 ;r3 As==00
  jz  $-14      ;abs 0x8854
  cmp #0, r13 ;r3 As==00
  jl  $-24      ;abs 0x884e
  rla r13   ;
  rla r11   ;
  br  #.SLLVM1
  cmp r13,  r12 ;
  jnc $+6       ;abs 0x8878
  sub r13,  r12 ;
  bis r11,  r15 ;
  clrc      
  rrc r11   ;
  clrc      
  rrc r13   ;
  br  #.SLLVM2
  )";

    constexpr const char *asm_remi = R"(
  .section .sllvm.text.<pm>.__mspabi_remi_<pm>,"ax",@progbits
  .globl __mspabi_remi_<pm>
  .p2align 1
  .type __mspabi_remi_<pm>,@function
  .equiv __mspabi_remu_<pm>, __mspabi_remi_<pm> ; TODO support remu properly
  .equiv _nds___mspabi_remi, __mspabi_remi_<pm>
  .equiv _ndd___mspabi_remi, __mspabi_remi_<pm>
__mspabi_remi_<pm>:
  push  r10   ;
  cmp #0, r12 ;r3 As==00
  jge $+40      ;abs 0x88fc
  clr.b r14   ;
  sub r12,  r14 ;
  mov r14,  r12 ;
  mov.b #1, r10 ;r3 As==01
.SLLVM3:
  cmp #0, r13 ;r3 As==00
  jge $+8       ;abs 0x88e8
  clr.b r14   ;
  sub r13,  r14 ;
  mov r14,  r13 ;
  mov.b #1, r14 ;r3 As==01
  call  #udivmodhi4_<pm>
  cmp #0, r10 ;r3 As==00
  jz  $+8       ;abs 0x88f8
  clr.b r13   ;
  sub r12,  r13 ;
  mov r13,  r12 ;
  pop r10   ;
  ret     
  clr.b r10   ;
  br  #.SLLVM3
  )";

    constexpr const char *asm_divi = R"(
  .section .sllvm.text.<pm>.__mspabi_divi_<pm>,"ax",@progbits
  .globl __mspabi_divi_<pm>
  .p2align 1
  .type __mspabi_divi_<pm>,@function
__mspabi_divi_<pm>:
  push	r10
  mov	r12,	r15
  mov	r13,	r14
  mov	#udivmodhi4,r11
  cmp	#0,	r12
  jge	$+54
  clr.b	r12
  sub	r15,	r12
  mov	r12,	r15
  cmp	#0,	r13
  jge	$+28
  mov.b	#1,	r10
.SLLVM4:
  clr	r13
  sub	r14,	r13
  clr.b	r14
  mov	r15,	r12
  call	r11
  cmp	#1,	r10
  jz	$+8
.SLLVM5:
  clr.b	r13
  sub	r12,	r13
  mov	r13,	r12
.SLLVM6:
  pop	r10
  ret			
  clr.b	r14
  call	r11
  br	#.SLLVM5
  clr.b	r14
  call	r11
  br	#.SLLVM6
  cmp	#0,	r13
  jge	$-10
  clr.b	r10
  br	#.SLLVM4
  )";

    constexpr const char *asm_fltulf = R"(
  .section .sllvm.text.<pm>.__mspabi_fltulf_<pm>,"ax",@progbits
  .globl __mspabi_fltulf_<pm>
  .p2align 1
  .type __mspabi_fltulf_<pm>,@function
__mspabi_fltulf_<pm>:
  nop     
  reti      
  )";

    constexpr const char *asm_addf = R"(
  .section .sllvm.text.<pm>.__mspabi_addf_<pm>,"ax",@progbits
  .globl __mspabi_addf_<pm>
  .p2align 1
  .type __mspabi_addf_<pm>,@function
__mspabi_addf_<pm>:
  nop     
  reti      
  )";

    constexpr const char *asm_mpyf = R"(
  .section .sllvm.text.<pm>.__mspabi_mpyf_<pm>,"ax",@progbits
  .globl __mspabi_mpyf_<pm>
  .p2align 1
  .type __mspabi_mpyf_<pm>,@function
__mspabi_mpyf_<pm>:
  nop     
  reti      
  )";

    constexpr const char *asm_aliases = R"(
  .equiv sllvm_lr1, sllvm_<pm>_lr1
  .equiv sllvm_lr1_addr, sllvm_<pm>_lr1_addr
    )";
  }
}

#endif
