//===- MSP430InstrLatencyInfo.cpp - Generate a Instruction Set Desc. --*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This tablegen backend is responsible for emitting the MSP430 instruction
//  latency information as used by the Nemesis defender.
//
//===----------------------------------------------------------------------===//

#include "CodeGenDAGPatterns.h"
#include "CodeGenInstruction.h"
#include "CodeGenSchedule.h"
#include "CodeGenTarget.h"
#include "PredicateExpander.h"
#include "SequenceToOffsetTable.h"
#include "TableGenBackends.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TableGen/Error.h"
#include "llvm/TableGen/Record.h"
#include "llvm/TableGen/TableGenBackend.h"

using namespace llvm;

namespace {

class MSP430InstrLatencyInfo {
  RecordKeeper &Records;
  CodeGenDAGPatterns CDP;

public:
  MSP430InstrLatencyInfo(RecordKeeper &R): Records(R), CDP(R) {}

  // run - Output the instruction set description.
  void run(raw_ostream &OS);

private:
};

} // end anonymous namespace


//===----------------------------------------------------------------------===//
// Main Output.
//===----------------------------------------------------------------------===//

// Calculates the integer value representing the BitsInit object
static inline uint64_t getValueFromBitsInit(const BitsInit *B) {
  assert(B->getNumBits() <= sizeof(uint64_t) * 8 && "BitInits' too long!");

  uint64_t Value = 0;
  for (unsigned i = 0, e = B->getNumBits(); i != e; ++i) {
    BitInit *Bit = cast<BitInit>(B->getBit(i));
    Value |= uint64_t(Bit->getValue()) << i;
  }
  return Value;
}

// The number of CPU clock cycles required for an instruction depends on the
// instruction format and the addressing modes used - not the instruction
// itself.
// TODO: Move this information to the TableGen files? (The actual instruction
//       latency values are subtarget-independent)
// TODO: This information should match the Sancus architecture (OpenMSP430)
static std::tuple<unsigned, unsigned, unsigned> ComputeLatency(Record *Inst) {
  unsigned latency = UINT_MAX;
  unsigned PCCorr = 0;
  unsigned OffsetOperandIdx = -1;

  if (   Inst->isSubClassOf("IForm")
      || Inst->isSubClassOf("I8rc")
      || Inst->isSubClassOf("I8mc")
      || Inst->isSubClassOf("I16rc")
      || Inst->isSubClassOf("I16mc") ) {
    uint16_t As = 0; // I8rc, I8mc, I16rc, I16mc use register mode
    if (Inst->isSubClassOf("IForm")) {
      As = getValueFromBitsInit(Inst->getValueAsBitsInit("As"));
    }
    auto Ad = getValueFromBitsInit(Inst->getValueAsBitsInit("Ad"));
    switch (As) {
      case 0:
        latency = (Ad == 0) ? 1 : 4;
        PCCorr = 1;
        break;
      case 1: 
        latency = 3;
        OffsetOperandIdx = 2;
        if (Ad == 1) {
          latency = 6;
          OffsetOperandIdx = 3;
        }
        break;
      case 2: latency = (Ad == 0) ? 2 : 5; break;
      case 3:
        latency = (Ad == 0) ? 2 : 5;
        PCCorr = 1;
        break;
      default:
        llvm_unreachable("Invalid As value");
    }
    // When the destination register is statically known, as is the case
    //  for "ret" and "br", correct the latency value
    if (PCCorr != 0) {
      if (Inst->getValue("rd")) {
        auto BI = Inst->getValueAsBitsInit("rd");
        if (BitInit::classof(BI->getBit(0))) { // Rd is statcally known
          if (getValueFromBitsInit(BI) == 0) { // Rd == PC
            latency += PCCorr;
            PCCorr = 0;
          }
        }
      }
    }
  } else if (   Inst->isSubClassOf("IIForm")
             || Inst->isSubClassOf("II16c")
             || Inst->isSubClassOf("II8c") ) {
    auto OpCode = getValueFromBitsInit(Inst->getValueAsBitsInit("Opcode"));
    if (OpCode == 6)  { // RETI
      latency = 5;
    }
    else {
      uint16_t As = 0; // II16c and II8c instructions use register mode
      if (Inst->isSubClassOf("IIForm")) {
        As = getValueFromBitsInit(Inst->getValueAsBitsInit("As"));
      }
      switch (As) {
        case 0:
          // Opcodes: PUSH=4, CALL=5
          switch (OpCode) {
            case 4:
              latency = 3;
              break;
            case 5:
              latency = 4;
              break;
            case 6:
              latency = 5;
              break;
            default:
              latency = 1;
              break; // RRA, RRC, SWPB, SXT
          }
          break;
        case 1:
          latency = (OpCode == 4 || OpCode == 5) ? 5 : 4;
          OffsetOperandIdx = 1;
          break;
        case 2:
          latency = (OpCode == 4 || OpCode == 5) ? 4 : 3;
          break;
        case 3:
          // Opcodes: PUSH=4, CALL=5
          switch (OpCode) {
            case 4:
              latency = Inst->getValue("imm") ? 4 : 5;
              break;
            case 5:
              latency = 5;
              break;
            default:
              latency = 4;
              break; // RRA, RRC, SWPB, SXT
          }
          break;
        default:
          llvm_unreachable("Invalid As value");
      }
    }
  } else if (Inst->isSubClassOf("CJForm")) {
    latency = 2;
  } else if (Inst->isSubClassOf("Pseudo")) {
    // TODO: What to do with pseudo instructions?
  } else if (Inst->isSubClassOf("StandardPseudoInstruction")) {
    // TODO: What to do with pseudo instructions?
  }
  else {
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
    Inst->dump();
#endif
    llvm_unreachable("Unknown instruction class");
  }

  return std::make_tuple(latency, PCCorr, OffsetOperandIdx);
}

// run - Emit the MSP430 instruction latency information
void MSP430InstrLatencyInfo::run(raw_ostream &OS) {
  emitSourceFileHeader("MSP430 Instruction Latency Information", OS);

  CodeGenTarget &Target = CDP.getTargetInfo();
  //const std::string &TargetName = Target.getName();
  StringRef Namespace = Target.getInstNamespace();
  //Record *InstrInfo = Target.getInstructionSet();

  OS << "#ifdef GET_INSTRINFO_LATENCY_DESC\n";
  OS << "#undef GET_INSTRINFO_LATENCY_DESC\n";

  OS << "namespace llvm {\n\n";
  OS << "namespace " << Namespace << " {\n";

  // TODO: Generate documentation containing the following information
  //
  // Table of (latency, PC-correction, offset operand idx) entries
  // For format-I MSP430 instructions, the instruction latency can differ
  // with one cycle when
  //    1) the destination addressing mode (Ad) is register mode
  //    2) and the program counter is the destination register.
  // This behavior is represented by the second element of a latency table entry.
  // The offset operand index is the index of the llvm::MachineOperand in
  // the llvm::MachineInstr that contains the offset value for indexed
  // addressing modes of the source operand, or -1 when a different
  // addressing mode is used. (see llvm::MachineInstr::getOperand(i))
  //
  OS << "static const unsigned LatencyTable[][3] = {\n";

  unsigned Num = 0;
  for (const CodeGenInstruction *II : Target.getInstructionsByEnumValue()) {
    Record *Inst = II->TheDef;
    auto L = ComputeLatency(Inst);

    OS << "/* " << Num++ << "*/ "
        << "{" 
        << std::get<0>(L) << ", " << std::get<1>(L) << ", " << std::get<2>(L)
        << "}, "
        << "// " << Namespace << "::" << Inst->getName() << "\n";
  }

  OS << "};\n";
  OS << "} // end namespace " << Namespace << "\n";
  OS << "} // end namespace llvm\n";
  OS << "#endif // GET_INSTRINFO_LATENCY_DESC\n";
}

namespace llvm {

void EmitMSP430InstrLatencyInfo(RecordKeeper &RK, raw_ostream &OS) { 
  MSP430InstrLatencyInfo(RK).run(OS);
}

} // end llvm namespace
