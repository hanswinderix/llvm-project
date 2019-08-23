#include <memory>

#include <llvm/CodeGen/MachineFrameInfo.h>
#include "MSP430.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/TargetLowering.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/ADT/SmallSet.h"

#include "llvm/Support/GraphWriter.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachinePostDominators.h"

using namespace llvm;

#define DEBUG_TYPE "msp430-nemesis-defender"

// This internal switch can be used to turn off the Nemesis defender
static cl::opt<bool>
    Enable(DEBUG_TYPE "-enable",
           cl::desc("Enable the MSP430 Nemesis defender"),
           cl::init(false), cl::Hidden);
static cl::opt<bool>
    EmitCFG(DEBUG_TYPE "-emit-cfg",
            cl::desc("Emit control flow graph (GraphViz)"),
            cl::init(false), cl::Hidden);

// TODO: Give credit to IfConversion pass?
//         (only if idea of branch-patterns is used)
// TODO: Refactor: Decompose in several classes
//        (taint analysis, shape matchers,...)

namespace {

/// Defends agains Nemesis attacks
class MSP430NemesisDefenderPass : public MachineFunctionPass {
public:

  /// A vector of defs (instruction ids) for a given register unit
  //TODO: using RegUnitDefs = SmallVector<size_t, 1>;
  using RegUnitDefs = std::vector<size_t>;
  /// All defs for a given MBB, indexed by register unit id
  using MBBDefsInfo = std::vector<RegUnitDefs>;

  /// A vector of dependencies to instructions, used for storing reaching
  //   definitions.
  using MIDepsInfo = SmallVector<MachineInstr *, 1>;
  /// All instruction dependencies for a given MBB, indexed by instruction id
  using MBBDepsInfo = std::vector<MIDepsInfo>;

  enum BranchClass {
    BCNotClassified, // MBB is unclassified
    BCFork,          // MBB is the entry of a fork shaped sub-CFG
    BCDiamond,       // MBB is the entry of a diamond shaped sub-CFG
    BCTriangle,      // MBB is the entry of a triangle shaped sub-CFG.
  };

  struct MBBInfo {
    bool IsDone                     : 1;
    bool IsAligned                  : 1;
    bool IsAnalyzable               : 1;
    bool IsBranch                   : 1; // Conditional or unconditional branch
    bool IsConditionalBranch        : 1;
    bool IsPartOfSensitiveRegion    : 1;
    bool IsLoopHeader               : 1;
    bool HasSecretDependentBranch   : 1;
    bool IsEntry                    : 1;
    bool IsReturn                   : 1;
    int TripCount = -1; /* Only relevant when IsLoopHeader is true */
                        /* LTODO: Add LoopInfo struct ? */
    size_t TerminatorCount = 0;
    MachineBasicBlock *BB = nullptr;
    MachineBasicBlock *Orig = nullptr; // Orignal contents of BB
    // Next is set when the next block can be statically determined
    MachineBasicBlock *Next = nullptr;
    MachineBasicBlock *TrueBB = nullptr;
    MachineBasicBlock *FalseBB = nullptr;
    MachineBasicBlock *FallThroughBB = nullptr;
    SmallVector<MachineOperand, 4> BrCond;
 
    // !TODO: Figure out if the implemenation cannot use the 
    //         MachineRegisterInfo (MRI) class for this...
    //        (there seems to be some redundancy with what I implemented
    //         and with what this class provides...)
    // => And what about the liveness information, why can't we reuse that?
    MBBDefsInfo Defs;
    MBBDepsInfo Deps;

    // TODO: Transform to OO design with polymorhic method align()
    //        and match() class method
    // Branch class info
    BranchClass BClass = BCNotClassified;
    union {
      struct {
        MachineBasicBlock *LeftBB; 
        MachineBasicBlock *RightBB;
      } Fork;
      struct {
      } Diamond;
      struct {
        MachineBasicBlock *DivBB;  // Block that diverges from the 'short path'
        MachineBasicBlock *JoinBB; // Block where the branches rejoin
      } Triangle;
    } BCInfo;

    MBBInfo() : IsDone(false), IsAligned(false), IsAnalyzable(false),
      IsBranch(false), IsConditionalBranch(false),
      IsPartOfSensitiveRegion(false), IsLoopHeader(false), 
      HasSecretDependentBranch(false),
      IsEntry(false), IsReturn(false) {}
  };

  // Return type of ComputeSuccessors
  struct Successors {
    std::vector<MachineBasicBlock *> Union;
    MachineLoop *Loop; // ! TODO: Beware of dangling pointers
  };

  // Recursive data type to represent the fingerprint of an aligned(!) sensitive
  // region. A sensitive region is either:
  //                - a sensitive branch,
  //                - a sensitive loop
  //                - a sensitive function
  // TODO: Document better
  struct Fingerprint {
    MachineBasicBlock *LoopHeader; // Enclosing Loop _or_ nullptr
    MachineBasicBlock *Head; // Head of fingerprint (can be empty but not null)

    // A possible empty vector of nested-fingerprint, rest-fingerprint) pairs
    //   (the MachineBasicBlock element of the pair can be empty but not null)
    std::vector<std::pair<std::shared_ptr<Fingerprint>, MachineBasicBlock *>> Tail;
  };

  MSP430NemesisDefenderPass() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "MSP430 Nemesis Defender"; }
  bool runOnMachineFunction(MachineFunction &MF) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  void releaseMemory() override;

  /// Pass identification, replacement for typeid.
  static char ID;

private:

  /// Maps instructions to their instruction Ids, relative to the beginning of
  /// their basic blocks.
  DenseMap<MachineInstr *, size_t> InstIds;
  /// The set of tainted instructions
  SmallPtrSet<const MachineInstr *, 10> TaintInfo;

  MachineFunction *MF;
  // The taint analysis procedure determines whether canonicalization is
  // required (i.e. when a sensitive region contains a return node).
  MachineBasicBlock *CanonicalExit = nullptr;
  MachineRegisterInfo *MRI;
  MachineLoopInfo *MLI;
  //const TargetLoweringBase *TLI;
  const TargetInstrInfo *TII;
  const TargetRegisterInfo *TRI;
  MachineDominatorTree *MDT;
  MachinePostDominatorTree *MPDT;

  /// TODO: OPTIMIZE: Analysis results indexed by basic block number
  //         SmallVector<MBBInfo, 4> BBAnalysis;
  std::map<MachineBasicBlock *, MBBInfo> BBAnalysis;
  MBBInfo *EntryBBI = nullptr;

  MBBInfo *GetInfo(MachineBasicBlock &MMB);
  std::vector<size_t> GetDefs(MBBInfo *BBI, size_t RU,
                              std::function<bool(size_t)> P);
  std::vector<size_t> GetDefsBefore(MBBInfo *BBI, size_t RU, size_t IID);
  std::vector<size_t> GetDefsAfter(MBBInfo *BBI, size_t RU, size_t IID);
  MachineBasicBlock *CreateMachineBasicBlock(
      StringRef debug, bool addToMF=false);
  MachineBasicBlock *CloneMBB(MachineBasicBlock *MBB, bool addToMF);

  void Taint(MachineInstr *MI);
  bool IsPartOfSensitiveRegion(const MachineInstr *MI);

  MachineBasicBlock *GetExitOfSensitiveBranch(MachineBasicBlock *Entry);

  void RemoveTerminationCode(MachineBasicBlock &MBB);
  void ReplaceSuccessor(MachineBasicBlock *MBB, MachineBasicBlock *Old,
                        MachineBasicBlock *New);

  std::shared_ptr<Fingerprint> GetFingerprint(MachineLoop *L);

  // Exit is the "join block" or the "point of convergence" of the originating
  //  sensitive region.
  Successors
  ComputeSuccessors(std::vector<MachineBasicBlock *> L, MachineBasicBlock *Exit);

  void AlignNonTerminatingInstructions(std::vector<MachineBasicBlock *> L);
  void AlignTerminatingInstructions(MachineBasicBlock *MBB);
  void AlignTwoWayBranch(MachineBasicBlock &MBB);

  MachineBasicBlock::iterator GetPosBeforeBranchingCode(MachineBasicBlock *MBB)
  const;

  // Returns information about 'taintedness' or 'secret-dependendentness' of
  //  machine instructions and basic block info.
  bool IsSecretDependent(MachineInstr *MI);
  bool IsSecretDependent(MBBInfo *BBI);

  void PrepareAnalysis();
  void FinishAnalysis();
  void CanonicalizeCFG();

  bool addDependency(MachineInstr *MI, MachineBasicBlock *MBB,
                     std::vector<size_t> &Defs);

  // RU is a register unit
  void ComputeDependencies(MachineInstr *MI, size_t RU, MachineBasicBlock *MBB,
                           SmallPtrSetImpl<MachineBasicBlock *> &Visited);

  void RegisterDefs(MBBInfo &BBI);

  bool MatchFork(MBBInfo &EBBI);
  bool MatchDiamond(MBBInfo &EBBI);
  bool MatchTriangle(MBBInfo &EBBI, bool DivOnFalse);

  void CompensateInstr(const MachineInstr &MI, MachineBasicBlock &MBB,
                       MachineBasicBlock::iterator MBBI);
  void CompensateCall(const MachineInstr &Call, MachineBasicBlock &MBB,
                      MachineBasicBlock::iterator MBBI);
  void SecureCall(MachineInstr &Call);

#if 0
  MachineBasicBlock::iterator AlignBlock(MachineBasicBlock &Source,
                                         MachineBasicBlock::iterator SI,
                                         MachineBasicBlock &Target,
                                         MachineBasicBlock::iterator TI);

  bool IsEnryOfPattern(MBBInfo &BBI, BranchClass BClass);

  void AlignTriangle(MBBInfo &EBBI);
  void AlignDiamond(MBBInfo &EBBI);
  void AlignFork(MBBInfo &EBBI);
#endif

  // TODO: Move analyzeCompare to TargetInstrInfo?
  bool analyzeCompare(const MachineInstr &MI, unsigned &SrcReg,
                      unsigned &SrcReg2, int &CmpMask, int &CmpValue) const;
  int GetLoopTripCount(MachineLoop *L);

  void RedoAnalysisPasses();

  void AnalyzeControlFlow(MBBInfo &BBI);
  void AnalyzeControlFlow(MachineBasicBlock &MBB);
  void AnalyzeControlFlow();

  void ReAnalyzeControlFlow(MachineBasicBlock &MBB);

  void VerifyControlFlowAnalysis();

  void ComputeReachingDefs();
  void PerformTaintAnalysis();
  void ClassifyBranches();

  void DetectOuterSensitiveBranches();
  void AnalyzeLoops();

  void AlignContainedRegions(MachineLoop *L);

  void SecureCalls();
  void AlignSensitiveBranches();

  void AlignSensitiveBranch(MBBInfo &BBI);
  std::vector<MachineBasicBlock *>
    AlignSensitiveLoop(MachineLoop *Loop, std::vector<MachineBasicBlock *> MBBs);
  std::vector<MachineBasicBlock *>
    AlignFingerprint(std::shared_ptr<Fingerprint> FP, std::vector<MachineBasicBlock *> MBBs);

  void DumpCFG();
  void DumpDebugInfo();
};

} // end anonymous namespace

char MSP430NemesisDefenderPass::ID = 0;

void MSP430NemesisDefenderPass::getAnalysisUsage(AnalysisUsage &AU) const {
  //AU.setPreservesCFG(); // TODO
  AU.addRequired<MachineLoopInfo>();
  AU.addRequired<MachineDominatorTree>(); // Because required by MLI (and must be
                                          //   maintained by this pass)
  AU.addRequired<MachinePostDominatorTree>();
  MachineFunctionPass::getAnalysisUsage(AU);
}

// TODO: Is there a better way to pass information about confidentiality from
//        frontend via middle-end to backend ?
static bool IsSecret(const Argument &Arg) {
  return Arg.getParent()->getAttributes().hasAttribute(Arg.getArgNo() + 1,
                                                       "secret");
}

static std::string GetName(MachineBasicBlock *MBB) {
  return MBB ? ("bb" + Twine(MBB->getNumber())).str() : "null";
}

static MachineBasicBlock *GetEntryMBB(MachineFunction *MF) {
  assert(MF->size() > 0);
  MachineBasicBlock *MBB = MF->getBlockNumbered(0);
  assert(MBB != nullptr);
  assert(MBB->pred_size() == 0);
  return MBB;
}

/// Analyze the terminators of a given MBB (uses TII->analyzeBranch):
///   - Detect branches
///   - Detect branch patterns
///   - Detect loops and upper iteration bound
///   - Look at the instructions at the end of the MBB (terminators)
///   - Be conservative: reject unsupported branch patterns if the branching
///      condition is based on secret information
/// Verify that the MBB conforms to the well-formedness criterion
///   (or do this in VerifyControlFlowAnalysis ?)
//
// TODO: Move this code to a seperate analysis pass
void MSP430NemesisDefenderPass::AnalyzeControlFlow(MBBInfo &BBI) {
  assert(! BBI.IsDone);

  auto MBB = BBI.BB;

  // General information
  BBI.FallThroughBB  = MBB->getFallThrough();

  BBI.TerminatorCount = std::distance(MBB->getFirstTerminator(), MBB->end());
  if (BBI.TerminatorCount <= 2) {

    BBI.IsEntry = MBB->pred_empty();
    if (BBI.IsEntry) {
      EntryBBI = &BBI;
    }

    if (BBI.TerminatorCount == 0) {
      // TODO: Not sure if the following assertions are all correct...
      assert(BBI.FallThroughBB != nullptr);
      assert(MBB->succ_size() == 1);
      assert(BBI.FallThroughBB == *MBB->succ_begin());
    }

    if (MBB->succ_size() == 1) {
      // There is only one successor, so the next block is statically known
      BBI.Next = *MBB->succ_begin();
    }

    // Analyze branch
    if (!TII->analyzeBranch(*MBB, BBI.TrueBB, BBI.FalseBB, BBI.BrCond)) {
      // analyzeBranch can invalidate the previous fall-through analysis
      BBI.FallThroughBB  = MBB->getFallThrough();
      BBI.IsAnalyzable = true;

      if (BBI.TrueBB != nullptr) {
        BBI.IsBranch = true;
        BBI.IsConditionalBranch = !BBI.BrCond.empty();

        if (BBI.IsConditionalBranch) {
          if (BBI.FalseBB == nullptr) {
            //LLVM_DEBUG(dbgs() << *BBI.BB);
            // This MBB must end with a conditional branch and a fallthrough.
            assert(BBI.FallThroughBB != nullptr);
            assert(BBI.FallThroughBB != BBI.TrueBB);
            BBI.FalseBB = BBI.FallThroughBB;
          }
          else {
            // This MBB must end with an unconitional branch followed by an
            //  unconditional.
            if (BBI.FallThroughBB != nullptr) {
              // There is an explicit branch to the fallthrough block (see
              //    code MBB::getFallThrough())
              // TODO: Optimize by removing one of the jumps (which might
              //        require to inverse the condition)
              BBI.FallThroughBB = nullptr;
            }
          }
        }
        else {
          // This must be an unconditonal branch
          if (BBI.FallThroughBB != nullptr) {
            // There is an explicit branch to the fallthrough block
            // TODO: Optimize by removing the branching code
            //       Delete the JMP if it's equivalent to a fall-through.
            BBI.FallThroughBB = nullptr;
          }
        }
      } else {
        // This must be a pure fallthrough block
        assert(BBI.TerminatorCount == 0);
        assert(BBI.FallThroughBB != nullptr);
      }
    } else {
      // There should be exactly one terminator
      assert(BBI.TerminatorCount == 1);
      assert(++(MBB->terminators().begin()) == MBB->terminators().end());
      MachineInstr *I = &*MBB->getFirstTerminator();

      if (I->isReturn()) {
        BBI.IsAnalyzable = true;
        BBI.IsReturn = true;
        assert(BBI.BB->isReturnBlock());
      }
    }
  }

  // Block cannot be analyzed
  if (! BBI.IsAnalyzable) {
    // Reject code that cannot be analyzed
    //  The RemoveTerminationCode (called by ComputeSuccessors) for example,
    //  depends on analyzable blocks.
    llvm_unreachable("TODO: Handle this case.");
  }
}

// !TODO: Fix this (RegUnit is a different concept than initialy thought...)
//         The analysis should mark every RegUnit as definded or used!
static size_t getRegUnit(const TargetRegisterInfo *TRI, size_t Reg) {
  MCRegUnitIterator RUI(Reg, TRI);
  assert(RUI.isValid());
  size_t RU = *RUI;
  ++RUI;
  assert(!RUI.isValid());
  return RU;
}

void MSP430NemesisDefenderPass::RegisterDefs(MBBInfo &BBI) {
  /// Current instruction number.
  size_t CurInstr = 0;
  for (MachineInstr &MI : BBI.BB->instrs()) {
    for (auto MO : MI.operands()) {
      // TODO: For now, only consider registers
      // TODO: To be portable, deal with two-operand instructions where
      //         a register can be both defined and used
      if (MO.isReg() && (!MO.isUse())) {
        assert(MO.getReg() > 0);
        assert(MO.isDef());
        auto RU = getRegUnit(TRI, MO.getReg());
        assert(RU < TRI->getNumRegUnits());
        assert(RU < BBI.Defs.size());
        BBI.Defs[RU].push_back(CurInstr);
      }
    }

    InstIds[&MI] = CurInstr;
    CurInstr++;
  }
}

MSP430NemesisDefenderPass::MBBInfo *
MSP430NemesisDefenderPass::GetInfo(MachineBasicBlock &MBB) {
#if 0  // Re-enable when BBAnalysis is a vector
  size_t N = MBB.getNumber();
  assert(N < BBAnalysis.size() && "Unexpected basic block number");
  return &BBAnalysis[N];
#else
  return &BBAnalysis[&MBB];
#endif
}

void MSP430NemesisDefenderPass::AnalyzeControlFlow(MachineBasicBlock &MBB) {
  auto BBI = GetInfo(MBB);

  if (! BBI->IsDone) {
    BBI->BB = &MBB;
    BBI->Defs.resize(TRI->getNumRegUnits());
    BBI->Deps.resize(MBB.size());

    AnalyzeControlFlow(*BBI);
    RegisterDefs(*BBI);

    BBI->IsDone = true;
  }
}

/// analyzeCompare - For a comparison instruction, return the source registers
/// in SrcReg and SrcReg2 if having two register operands, and the value it
/// compares against in CmpValue. Return true if the comparison instruction
/// can be analyzed.
bool MSP430NemesisDefenderPass::analyzeCompare(
    const MachineInstr &MI, unsigned &SrcReg, unsigned &SrcReg2, int &CmpMask,
    int &CmpValue) const {
  switch (MI.getOpcode()) {
    default: break;
    case MSP430::CMP8ri:
    case MSP430::CMP8rc:
    case MSP430::CMP16ri:
    case MSP430::CMP16rc:
      SrcReg = MI.getOperand(0).getReg();
      SrcReg2 = 0;
      CmpMask = ~0;
      CmpValue = MI.getOperand(1).getImm();
      return true;
    case MSP430::SUB8ri:
    case MSP430::SUB8rc:
    case MSP430::SUB16ri:
    case MSP430::SUB16rc:
      SrcReg = MI.getOperand(0).getReg();
      SrcReg2 = 0;
      CmpMask = ~0;
      CmpValue = MI.getOperand(2).getImm();
      return true;
    case MSP430::CMP8rr:
    case MSP430::CMP16rr:
      SrcReg = MI.getOperand(0).getReg();
      SrcReg2 = MI.getOperand(1).getReg();
      CmpMask = ~0;
      CmpValue = 0;
      return true;
    case MSP430::BIT8ri:
    case MSP430::BIT16ri:
      SrcReg = MI.getOperand(0).getReg();
      SrcReg2 = 0;
      CmpMask = MI.getOperand(1).getImm();
      CmpValue = 0;
      return true;
    case MSP430::CMP16mc:
    case MSP430::CMP16mi:
    case MSP430::CMP16mm:
    case MSP430::CMP16mn:
    case MSP430::CMP16mp:
    case MSP430::CMP16mr:
    case MSP430::CMP16rm:
    case MSP430::CMP16rn:
    case MSP430::CMP16rp:
    case MSP430::CMP8mc:
    case MSP430::CMP8mi:
    case MSP430::CMP8mm:
    case MSP430::CMP8mn:
    case MSP430::CMP8mp:
    case MSP430::CMP8mr:
    case MSP430::CMP8rm:
    case MSP430::CMP8rn:
    case MSP430::CMP8rp:
    case MSP430::BIT16mc:
    case MSP430::BIT16mi:
    case MSP430::BIT16mm:
    case MSP430::BIT16mn:
    case MSP430::BIT16mp:
    case MSP430::BIT16mr:
    case MSP430::BIT16rc:
    case MSP430::BIT16rm:
    case MSP430::BIT16rn:
    case MSP430::BIT16rp:
    case MSP430::BIT16rr:
    case MSP430::BIT8mc:
    case MSP430::BIT8mi:
    case MSP430::BIT8mm:
    case MSP430::BIT8mn:
    case MSP430::BIT8mp:
    case MSP430::BIT8mr:
    case MSP430::BIT8rc:
    case MSP430::BIT8rm:
    case MSP430::BIT8rn:
    case MSP430::BIT8rp:
    case MSP430::BIT8rr:
      // TODO
      return false;
  }

  return false;
}

static bool Defines(MachineOperand &MO, unsigned Reg) {
  return (MO.isReg() && MO.isDef() && (MO.getReg() == Reg));
}

static bool IsCopyConstant(MachineInstr *MI, int &V) {
  switch(MI->getOpcode()) {
    case MSP430::MOV8ri:
    case MSP430::MOV16ri:
    case MSP430::MOV8rc:
    case MSP430::MOV16rc:
      V = MI->getOperand(1).getImm();
      return true;
  }
  return false;
}

static bool IsAddConstant(MachineInstr *MI, int &V) {
  switch(MI->getOpcode()) {
    case MSP430::ADD8ri:
    case MSP430::ADD16ri:
    case MSP430::ADD8rc:
    case MSP430::ADD16rc:
      V = MI->getOperand(2).getImm();
      return true;
    case MSP430::SUB8ri:
    case MSP430::SUB16ri:
    case MSP430::SUB8rc:
    case MSP430::SUB16rc:
      V = -MI->getOperand(2).getImm();
      return true;
  }
  return false;
}

static MSP430CC::CondCodes reverseCondCode(MSP430CC::CondCodes CC) {
  switch (CC) {
    case MSP430CC::COND_E : return MSP430CC::COND_NE;
    case MSP430CC::COND_NE: return MSP430CC::COND_E;
    case MSP430CC::COND_L : return MSP430CC::COND_GE;
    case MSP430CC::COND_GE: return MSP430CC::COND_L;
    case MSP430CC::COND_HS: return MSP430CC::COND_LO;
    case MSP430CC::COND_LO: return MSP430CC::COND_HS;
    default: llvm_unreachable("Invalid cond code");
  }
}

// TODO: MSP430 specific
int MSP430NemesisDefenderPass::GetLoopTripCount(MachineLoop *L) {

  assert(L->getHeader() != nullptr);

  // Get the unique loop predecessor. This is required to be able to
  //  determine the initial value of the loop's induction variable.
  auto *Pre = L->getLoopPredecessor();
  assert(Pre != nullptr);

  // Get unique loop control block
  MachineBasicBlock *ControlBlock = L->findLoopControlBlock();
  if (ControlBlock == nullptr)
    llvm_unreachable("No unique exit block");

  assert(ControlBlock == L->getLoopLatch());

  // Get the compare instruction, or to be more precise the instruction that
  //  defines SR. Require it to be in the exit block.
  MachineInstr *CMPI = nullptr;
  auto TI = ControlBlock->getFirstTerminator();
  assert(TI != ControlBlock->end());
  auto II = ControlBlock->begin();
  while (II != TI) {
    // !TODO: Optimize, use BBI->Defs for this and start looking from the end
    //             of MBB
    for (auto &MO : II->operands()) {
      if (Defines(MO, MSP430::SR)) {
        CMPI = &*II;
      }
    }
    II++;
  }
  assert(CMPI != nullptr);

  // Analyze the compare instruction, or to be more precise the instruction
  //  that defines SR
  unsigned IVReg, Reg2;
  int CmpMask, CmpValue;
  if (! analyzeCompare(*CMPI, IVReg, Reg2, CmpMask, CmpValue))
    llvm_unreachable("Unable to analyze compare (1)");

  assert(IVReg != 0);
  if (Reg2 != 0) {
    MF->viewCFG();
    LLVM_DEBUG(dbgs() << GetName(L->getHeader()) << "\n");
    llvm_unreachable("Unable to analyze compare (2)");
  }
  //assert(CmpValue != 0);
  //assert(CmpMask == ~0);

  // Find out where IVReg (induction variable register) is updated
  //   For now, require that this is in the predecessor block
  MachineInstr *IVInI = nullptr;
  while ( (Pre != nullptr) && (IVInI == nullptr) ) {
    II = Pre->begin();
    TI = Pre->getFirstTerminator();
    while (II != TI) {
      // !TODO: Optimize, use BBI->Defs for this and start looking from the end
      //             of MBB
      for (auto &MO : II->operands()) {
        if (Defines(MO, IVReg)) {
          IVInI = &*II;
        }
      }
      II++;
    }

    /* Keep searching as long as there is a unique predecessor */
    if (Pre->pred_size() == 1) {
      Pre = *Pre->pred_begin();
    }
  }
  assert(IVInI != nullptr);

  assert(IVInI->getOperand(0).getReg() == IVReg);
  int IVInV;
  if (! IsCopyConstant(IVInI, IVInV)) {
    llvm_unreachable("Mov expected");
  }

  // Find out where IVReg (induction variable register) is updated
  //   For now, require that this is in the exit block
  II = ControlBlock->begin();
  TI = ControlBlock->getFirstTerminator();
  MachineInstr *IVUpI = nullptr;
  while (II != TI) {
    // !TODO: Optimize, use BBI->Defs for this and start looking from the end
    //             of MBB
    for (auto &MO : II->operands()) {
      if (Defines(MO, IVReg)) {
        IVUpI = &*II;
      }
    }
    II++;
  }
  assert(IVUpI != nullptr);

  assert(IVUpI->getOperand(0).getReg() == IVReg);
  int IVUpV;
  if (! IsAddConstant(IVUpI, IVUpV)) {
    llvm_unreachable("Add expected");
  }

  // Compute trip count
  int TripCount = 0;
  auto BBI = GetInfo(*ControlBlock);
  assert(BBI->BrCond.size() == 1);
  auto CC = static_cast<MSP430CC::CondCodes>(BBI->BrCond[0].getImm());
  if (L->contains(BBI->FalseBB)) {
    //MF->viewCFG();
    LLVM_DEBUG(dbgs() << GetName(L->getHeader()) << "\n");
    assert(! L->contains(BBI->TrueBB));
    CC = reverseCondCode(CC);
  }
  else {
    assert(L->contains(BBI->TrueBB));
  }

  switch (CC) {
    /* JC, JHS */
    case MSP430CC::COND_HS:
      assert(IVInV > CmpValue);
      assert(IVUpV < 0);
      TripCount = (CmpValue - IVInV) / (IVUpV); // TODO
      break;

    /* JNC, JLO */
    case MSP430CC::COND_LO:
      assert(IVInV < CmpValue);
      assert(IVUpV > 0);
      TripCount = (CmpValue - IVInV) / (IVUpV); // TODO
      break;

    /* JNE, JNZ */
    case MSP430CC::COND_NE:
      if (IVInV < CmpValue) {
        assert(IVUpV > 0);
        TripCount = (CmpValue - IVInV) / (IVUpV); // TODO
      }
      else {
        assert(IVInV > CmpValue);
        assert(IVUpV < 0);
        TripCount = (CmpValue - IVInV) / (IVUpV); // TODO
      }
      break;

    /* JGE */
    case MSP430CC::COND_GE:
    /* JL */
    case MSP430CC::COND_L :
    /* JN */
    case MSP430CC::COND_N :
    /* JE, JZ */
    case MSP430CC::COND_E :
    default:
      llvm_unreachable("Unsupported condition code");
  }

  LLVM_DEBUG(dbgs() << "TRIP COUNT=" << TripCount);
  LLVM_DEBUG(dbgs() << " CC="    << CC);
  LLVM_DEBUG(dbgs() << " BEGIN=" << IVInV);
  LLVM_DEBUG(dbgs() << " STEP="  << IVUpV);
  LLVM_DEBUG(dbgs() << " END="   << CmpValue);
  LLVM_DEBUG(dbgs() << "\n");

  return TripCount;
}

void MSP430NemesisDefenderPass::AnalyzeControlFlow() {
  for (MachineBasicBlock &MBB : *MF) {
    AnalyzeControlFlow(MBB);
  }
}

void MSP430NemesisDefenderPass::ReAnalyzeControlFlow(MachineBasicBlock &MBB) {
  auto BBI = GetInfo(MBB);

  // TODO: Not every field below should be reset
  //         (maybe its better to move this code to the MBBInfo struct)
  BBI->IsDone = false;
  // IsAligned status cannot be reset
  //BBI->IsAligned = false;
  BBI->IsAnalyzable = false;
  BBI->IsBranch = false;
  BBI->IsConditionalBranch = false;
  // HasSecretDependentBranch is set in PerformTaintAnalysis, not in
  //  AnalyzeControlFlow
  //BBI->HasSecretDependentBranch = false; 
  // IsPartOfSensitiveRegion is set during outer region analysis
  /// BBI->IsPartOfSensitiveRegion
  BBI->IsEntry = false;
  BBI->IsReturn = false;
  BBI->BB = nullptr;
  // There is no need to reset the original contents
  //BBI->Orig = nullptr;

  // Dont' touch loop analysis (loop analysis should not change)
  // BBI->IsLoopHeader = false;
  // BBI->TripCount = 0;
  BBI->Next = nullptr;
  BBI->TrueBB = nullptr;
  BBI->FalseBB = nullptr;
  BBI->FallThroughBB = nullptr;
  BBI->TerminatorCount = 0;
  BBI->BrCond.clear();
  BBI->Defs.clear();
  BBI->Deps.clear();
  std::memset(&BBI->BCInfo, 0, sizeof(BBI->BCInfo));

  AnalyzeControlFlow(MBB);
}

// Verify the analysis results, assert assumptions
// Also check well-formedness criterion of termination code
//   (or does this belong in the AnalyzeControlFlow method ?)
void MSP430NemesisDefenderPass::VerifyControlFlowAnalysis() {
  // Every block should have been analyzed
  for (MachineBasicBlock &MBB : *MF) {
#if 0  // Re-enable when BBAnalysis is a vector
    size_t N = MBB.getNumber();
    assert(N < BBAnalysis.size() && "Unexpected basic block number");
    assert(BBAnalysis[N].IsDone);
#else
    assert(BBAnalysis.find(&MBB) != BBAnalysis.end());
    assert(BBAnalysis[&MBB].IsDone);
#endif
    auto BBI = GetInfo(MBB);

    // Verify well-formedness criterion
    if (BBI->IsAnalyzable) {
      //
      // o Maximum two termination instructions are allowed
      assert(BBI->TerminatorCount <= 2);

      // o For unconditional branches, only the following addressing modes
      //       will be supported. Reject all others (set IsAnalyzable to false).
      //   - immediate (3 cycles)
      //   - symbolic (3 cycles)
      //   - absolute (3 cycles)
      // TODO
    }
  }

  // There should be exaclty one entry point
  assert(EntryBBI != nullptr);
  assert(EntryBBI->BB == GetEntryMBB(MF) && "Unexpected entry block");
  assert(std::count_if(BBAnalysis.begin(), BBAnalysis.end(),
                       [](std::pair<const MachineBasicBlock *, MBBInfo> x) {
                         return x.second.IsEntry;
                       }) == 1);
}

// Returns all the definitions of register unit RU in BII.BB for which
//   predicate P evaluates to true
std::vector<size_t>
MSP430NemesisDefenderPass::GetDefs(MBBInfo *BBI, size_t RU,
                                   std::function<bool(size_t)> P) {
  std::vector<size_t> R;
  R.resize(BBI->Defs[RU].size());
  auto I =
    std::copy_if(BBI->Defs[RU].begin(), BBI->Defs[RU].end(), R.begin(), P);
  R.resize(std::distance(R.begin(), I));
  return R;
}

// Returns all the definitions of register unit RU in BII.BB that come before
// the given instruction identifier.
std::vector<size_t>
MSP430NemesisDefenderPass::GetDefsBefore(MBBInfo *BBI, size_t RU, size_t IID) {
  return GetDefs(BBI, RU, [IID](size_t DIID) { return DIID < IID; });
}

// Returns all the definitions of register unit RU in BII.BB that come after
// the given instruction identifier.
std::vector<size_t>
MSP430NemesisDefenderPass::GetDefsAfter(MBBInfo *BBI, size_t RU, size_t IID) {
  return GetDefs(BBI, RU, [IID](size_t DIID) { return DIID > IID; });
}

// TODO: It is the responsibility of callers to CreateMachineBasicBlock to call
//  AnalyzeControlFlow on the created block when appropriate. This should be
//  made more robust and future proof as callers are probably going to forget
//  this.
MachineBasicBlock * MSP430NemesisDefenderPass::CreateMachineBasicBlock(
    StringRef debug, bool addToMF) {
  MachineBasicBlock *MBB = MF->CreateMachineBasicBlock(nullptr);
  if (addToMF) {
    MF->push_back(MBB);
  }
  LLVM_DEBUG(dbgs() << "New MBB: " << GetName(MBB) << " (" << debug << ")\n");
  return MBB;
}

// Clones a MBB (contents only)
// TODO: It is the responsibility of callers to CloneBlock to call
//  AnalyzeControlFlow on the created block when appropriate. This should be
//  made more robust and future proof as callers are probably going to forget
//  this.
MachineBasicBlock *MSP430NemesisDefenderPass::CloneMBB(
    MachineBasicBlock *MBB, bool addToMF) {
  //LLVM_DEBUG(dbgs() << "Cloning " << GetName(MBB) << "\n");
  MachineBasicBlock *Clone = CreateMachineBasicBlock("clone", addToMF);
  for (auto &MI : *MBB) {
    // TODO: Use MF->CloneMachineInstrBundle() ?
    Clone->push_back(MF->CloneMachineInstr(&MI));
    // TODO: What is the difference with MI.Clone() ?
    //
    //!!TODO How to deal with instruction that refer to other MBBs
    //        and that are no jump-instructions (e.g. just take the adresss
    //        of a MBB, ...)
    //        In the clone they should probably refer to another MBB
    //        This should be handled case by case, just as changing the
    //        termination instructions of the clone, and as adapting the
    //        CFG ...
  }

  // Keep track of the original contents
  // TODO: This should be refactored (addToMF is a bad name to start with)
  //        addToMF is only false, when the original clone is being made
  //        (original clone has a block number of -1)
  //        in all other cases, the MBB is the original clone
  if (addToMF) {
    assert(MBB->getNumber() == -1);
    GetInfo(*Clone)->Orig = MBB;
  }

  return Clone;
}

/// Removes the branching code at the end of the specific MBB.
/// Non-branching termination code is ignored.
/// TODO: This function is redundant to TII->removeBranch(MBB)
void MSP430NemesisDefenderPass::RemoveTerminationCode(MachineBasicBlock &MBB) {
  MBBInfo *BBI = GetInfo(MBB);
  assert(BBI->IsAnalyzable);

  if (BBI->IsBranch) {
    assert(BBI->TerminatorCount > 0);
    TII->removeBranch(MBB);
  }
  else if (BBI->IsReturn) {
    MachineBasicBlock::iterator I = MBB.end();
    I--;
    assert(I->getOpcode() == MSP430::RET);
    I->eraseFromParent();
  }
  else {
    // This must be a pure fallthrough block
    //  So, no branch to remove
    assert (BBI->TerminatorCount == 0);
    assert(BBI->FallThroughBB != nullptr);
  }
}

// Updates CFG, BB analysis and the MBBs' termination code accordingly
//
// Re-analyzes the CF for MBB
void MSP430NemesisDefenderPass::ReplaceSuccessor(
    MachineBasicBlock *MBB, MachineBasicBlock *Old, MachineBasicBlock *New) {

  assert(MBB->isSuccessor(Old));

  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // 1. Update CFG (A correct CFG is a precondition for TII->insertBranch)
  MBB->replaceSuccessor(Old, New);

  // 2. Update termination code
  RemoveTerminationCode(*MBB);
  auto BBI = GetInfo(*MBB);
  if (BBI->IsBranch) {
    if (BBI->TrueBB == Old) BBI->TrueBB = New;
    if (BBI->FalseBB == Old) BBI->FalseBB = New;
    if (BBI->IsConditionalBranch) {
      TII->insertBranch(*MBB, BBI->TrueBB, BBI->FalseBB, BBI->BrCond, DL);
    }
    else {
      assert(BBI->FallThroughBB == nullptr);
      TII->insertBranch(*MBB, BBI->TrueBB, nullptr, {}, DL);
    }
  }
  else {
    assert(! BBI->IsReturn); // A block with a successor cannot return
    assert(BBI->FallThroughBB != nullptr);
    assert(BBI->FallThroughBB == Old);
    BBI->FallThroughBB = nullptr;
    TII->insertBranch(*MBB, New, nullptr, {}, DL);
  }

  // Update control-flow analysis
  ReAnalyzeControlFlow(*MBB);
}

// !TODO: Should it be "MOV16rc" or "MOV16ri" ??? (because of immediate
//        value of one) (look also at other places for this choice)
//      REMARK: When *rc variant is used, "nop" is generated instead of
//      instruction  in the case of the dummy instructions
//          (see buildNop1, buildNop2,...). and consequently, test-nemdef
//          unit test suite fails.
static void BuildNOP1(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  #0, R3       ; 1 cycle , 1 word
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16ri), MSP430::CG).addImm(0);
}

static void BuildNOP2(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

#if 0
  // TODO: This might be problemtic, as entering a JMP in the middle
  //        of a MBB breaks the well-formedness of the MBB
  // JMP  $+2          ; 2 cycles, 1 word
  BuildMI(MBB, I, DL, TII->get(MSP430::JMP)).addImm(0);
#else
  // TODO: According to the the MSP430 manual, this is an illegal
  //        instruction, but OpenMSP430 seems to accept this.
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16ri), MSP430::CG).addImm(42);
#endif
}

static void BuildNOP3(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  2(PC), PC    ; 3 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16rm), MSP430::PC)
      .addReg(MSP430::PC)
      .addImm(2);
}

static void BuildNOP4(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // BIC  #0, 0(R4)    ; 4 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::BIC16mi), MSP430::FP)
      .addImm(0)
      .addImm(0);
}

static void BuildNOP5(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  @R4, 0(R4)   ; 5 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16mn), MSP430::FP)
      .addImm(0)
      .addReg(MSP430::FP);
}

static void BuildNOP6(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  0(R4), 0(R4) ; 6 cycles, 3 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16mm), MSP430::FP)
      .addImm(0)
      .addReg(MSP430::FP)
      .addImm(0);
}

// TODO: MSP430 specific
// According to the MSP430 manual, a branch instruction always takes two cycles
// two execute, independent on whether a branch is taken or not
static void BuildBranchCompensator(MachineBasicBlock &MBB, 
                                   MachineBasicBlock::iterator I,
                                   const TargetInstrInfo *TII) {
  BuildNOP2(MBB, I, TII);
}

// Retrieves the fingerprint of the loop. The fingerprint is a slice of the 
//  loop,
//    a list of dummy instructions that represents a sequence of instruction
//    types in all possible paths of the aligned loop.

// Note that the fingerprint does not include the latch blocks of a loop
//  because it is not clear yet what the exact fingerprint of the latch block
//  will look like.
//
// PRE: The loop region (from header to latch) must be aligned for the
//       fingerprint to be correct. This means alignment of
//         - terminating instructions
//         - non-terminating instructions
//         - two-way branches
//
// Any control-flow path from loop-header to loop-latch should do, because
//  the loop region is already aligned (precondition) which means that all
//  possible paths from header to latch are observably equivalent.
//  Therefore, do a DFS traversal through the sensitive region.
std::shared_ptr<MSP430NemesisDefenderPass::Fingerprint>
MSP430NemesisDefenderPass::GetFingerprint(MachineLoop *L) {

  std::shared_ptr<Fingerprint> Result(new Fingerprint);

  MachineBasicBlock *FPBB = CreateMachineBasicBlock("fingerprint1", false);

  // Outer loop
  Result->LoopHeader = L->getHeader();
  assert(Result->LoopHeader != nullptr && "Loop is not well-formed");
  Result->Head = FPBB;

  // According to the well-formedness criterion, the last block of a DFS in
  //   any path should be the loop latch
  auto Latch = L->getLoopLatch();
  assert(Latch != nullptr);
  auto CurBB = L->getHeader();
  MachineBasicBlock *PrevBB = nullptr;

  // Make sure this loop terminates (i.e when latch post-dominates the header)
  assert(MPDT->dominates(Latch, CurBB));
  std::set<MachineBasicBlock *> Visited;

  while (CurBB != Latch) {
    assert(Visited.find(CurBB) == Visited.end());
    Visited.insert(CurBB);

    auto L2 = MLI->getLoopFor(CurBB);
    assert(L2 != nullptr);

    if (L2 != L) {
      assert(L2->getLoopPreheader() == PrevBB && "Well-formed loop expected");

      // Deal with nested loop
      FPBB = CreateMachineBasicBlock("fingerprint2", false);
      Result->Tail.push_back(std::make_pair(GetFingerprint(L2), FPBB));

      // Continue with thex loop-exit block
      assert(CurBB != nullptr && "Well-formed loop expected");
      PrevBB = CurBB;
      CurBB = L2->getExitBlock();
    }
    else {
      auto BBI = GetInfo(*CurBB);

      for (auto &MI : *CurBB) {
        if (MI.isCall()) {
          CompensateCall(MI, *FPBB, FPBB->end());
        }
        else {
          CompensateInstr(MI, *FPBB, FPBB->end());
        }
      }

      // All sensitive regions should be aligned by now, so the number
      // of statements should be the same, for any path that is taken
      // Still, caution has to be taken for two-way branches.
      if (BBI->IsConditionalBranch) {
        assert(CurBB->succ_size() == 2);
        // Follow the false path to avoid compensating for the
        //   1) the "JMP" instruction from the (JCC, JMP) pair _and_
        //   2) the JMP-compensated instruction in the true path
        // to the fingerprint.
        assert(BBI->BB->isSuccessor(BBI->TrueBB));
        assert(BBI->BB->isSuccessor(BBI->FalseBB));
        PrevBB = CurBB;
        CurBB = BBI->FalseBB;
      } else {
        assert(CurBB->succ_size() == 1);
        PrevBB = CurBB;
        CurBB = *CurBB->succ_begin();
      }
    }
  }

  return Result;
}

void MSP430NemesisDefenderPass::AlignTwoWayBranch(MachineBasicBlock &MBB) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  auto BBI = GetInfo(MBB);

  assert(BBI->HasSecretDependentBranch);
  assert(BBI->IsConditionalBranch && (BBI->FallThroughBB == nullptr) );
  assert(BBI->TerminatorCount == 2);

  auto T = MBB.getFirstTerminator();
  assert(T++->isConditionalBranch());
  assert(T++->isUnconditionalBranch());
  assert(T == MBB.end());

  LLVM_DEBUG(dbgs() << GetName(&MBB) << ": Align two-way branch\n");

#if 1
  // Compensate for the unconditional jump when the conditional jump has
  // been taken (in the true path).
  BuildBranchCompensator(*BBI->TrueBB, BBI->TrueBB->begin(), TII);
#else
  // Add a "jump block" between MBB and TrueBB to contain a single
  // unconditional jump statement)
  auto JBB = CreateMachineBasicBlock("align", true);
  BuildMI(*JBB, JBB->begin(), DL, TII->get(MSP430::JMP)).addMBB(BBI->TrueBB);
  JBB->addSuccessor(BBI->TrueBB);

  // Update MBB accordingly
  ReplaceSuccessor(&MBB, BBI->TrueBB, JBB);
  RemoveTerminationCode(MBB);
  TII->insertBranch(MBB, JBB, BBI->FalseBB, BBI->BrCond, DL);

  // Update control flow analysis
  ReAnalyzeControlFlow(MBB);
  AnalyzeControlFlow(*JBB);

  auto JBBI = GetInfo(*JBB);
  JBBI->Orig = CloneMBB(JBB, false); // TODO: Refactor the bookkeeping of 
                                     //        the original block contents
  assert(JBB->succ_size() == 1);
  assert(JBB->pred_size() == 1);
#endif
}

// Returns
//   1) when one of the direct successors represents the header of a loop
//      - Successors.Loop points to the detected loop
//      - Successors.Union represents the union of the direct successors of
//         every MMB in MBBs (modulo the Loop header )
//     The CFG will not be mutated.
//
//   2) otherwise
//      - Successors.Loop will be nullptr
//      - Successors.Union represents the union of the direct successors of
//         every MMB in MBBs
//      Possibly mutates the MF (and corresonding CFG) in order for the
//      preconditions of AlignBlocks() to be valid.
//
// PRE: All MBB in MBBs are part of a SESE-region
// POST: R.Union does not contain any duplicate blocks
//
// Param Exit is the "join block" or the "point of convergence" of the
// originating sensitive region.
//
// TODO: When a new basic block is added, a number of analyses, such
//   as CF analysis, have to be (re)done and some data structures,
//   such as the CFG, need to be maintained. This occurs at multiple
//   locations in this pass and should be factored out in a common
//   method.
MSP430NemesisDefenderPass::Successors
MSP430NemesisDefenderPass::ComputeSuccessors(
    std::vector<MachineBasicBlock *> MBBs, MachineBasicBlock *Exit) {
  LLVM_DEBUG(dbgs() << "> Compute successors: ");
  LLVM_DEBUG(for (auto MBB: MBBs) dbgs() << GetName(MBB) << ", ");
  LLVM_DEBUG(dbgs() << "\n");

  std::set<MachineBasicBlock *> Set;
  Successors R;
  R.Loop = nullptr;

  auto IsDone = [Exit](MachineBasicBlock * MBB) {
    return MBB->succ_size() == 1 && (*MBB->succ_begin() == Exit);
        // TODO: Check that the transformation in this pass does not invalidate
        //        the (post)dominator tree analysis
  };

  if ( ! std::all_of(MBBs.begin(), MBBs.end(), IsDone) ) {

    // Loop detector
    //   Deal with possible loops first
    //   => Check if one of the successors is the start of a new loop
    for (auto MBB : MBBs) {
      auto L1 = MLI->getLoopFor(MBB);
      for (auto S : MBB->successors()) {
        auto L2 = MLI->getLoopFor(S);
        if ((L2 != nullptr) && (L1 != L2)) {
          R.Loop = L2; // Loop found

          LLVM_DEBUG(dbgs() << "Loop found:"
                            << " header=" << GetName(L2->getHeader())
                            << " latch=" << GetName(L2->getLoopLatch())
                            << " exit=" << GetName(L2->getExitBlock())
                            << "\n");

          assert(MLI->isLoopHeader(S));
          // TODO: When a loop has more than one predecessor,
          //    getLoopPredecessor() returns nullptr. Fix this by duplicating
          //    the loop for every predecessor (can be optimized if every
          //    predecessor initializes the induction variable with the same
          //    value)
          // The LLVM MSP430 backend, for example, generates this kind of loop
          // when multiplying by two (see compound-conditional-expr.c)
          auto P = L2->getLoopPredecessor();
          assert(P != nullptr); // See comment above
          assert(P == MBB);
          assert(S->pred_size() == 2); // MBB and Latch
          assert(L2->getLoopPreheader() != nullptr);
          auto LL = L2->getLoopLatch();
          assert(L2->getLoopLatch() && "Loops with multiple latch blocks are not supported");
          auto E = L2->getExitBlock();
          assert(E && "Loops with multiple exit blocks are not supported");

          auto BBI = GetInfo(*LL);
          assert(BBI->IsConditionalBranch);
          assert(BBI->BrCond.size() == 1);
          assert(BBI->BB->succ_size() == 2); // See well-formedness criterion
          assert(BBI->TrueBB != nullptr);
          assert(BBI->FalseBB != nullptr);
          assert(L2->contains(BBI->TrueBB) || L2->contains(BBI->FalseBB));

#if 0
          auto IPDom = (*MPDT)[S]->getIDom(); // Immediate post-dominator
          assert(IPDom->getBlock() != nullptr && "Loop is not well-formed");
          assert(IPDom->getBlock() == E && "Loop is not well-formed");
#endif

          if (L2->contains(BBI->TrueBB)) {
            assert(!L2->contains(BBI->FalseBB));
          }
          else {
            assert(L2->contains(BBI->FalseBB));
          }

          break; /* The beginning of a loop is found. Stop looking.*/
        }
      }

      if (R.Loop != nullptr) /* A loop is found, stop looking.*/
        break;
    }

    if (R.Loop != nullptr) {

      // Deal with detected loop
      for (auto MBB : MBBs) {
        for (auto S : MBB->successors()) {
          if (S != R.Loop->getHeader()) {
            auto SBBI = GetInfo(*S);
            assert(! SBBI->IsAligned);

            // TODO: Blocks with the same successor can share an empty block
            auto EmptyMBB = CreateMachineBasicBlock("empty-for-loopif", true);
            GetInfo(*EmptyMBB)->Orig = CloneMBB(EmptyMBB, false);
            ReplaceSuccessor(MBB, S, EmptyMBB);
            EmptyMBB->addSuccessor(S);
            TII->insertBranch(*EmptyMBB, S, nullptr, {}, DebugLoc());
            AnalyzeControlFlow(*EmptyMBB);
            R.Union.push_back(EmptyMBB);
          }
        }
      }
    }
    else {
      R.Loop = nullptr;

      MachineBasicBlock *EmptyMBB = nullptr;

      // No loops found
      std::map<MachineBasicBlock *, MachineBasicBlock *> Clones; // DenseMap?
      for (auto MBB : MBBs) {
        for (auto S : MBB->successors()) {
          auto BBI = GetInfo(*MBB);
          auto SBBI = GetInfo(*S);

          // Ignore self-cycles
          // self-cycles should have been dealt with already, just like any
          // other loop (i.e. no single-block loop) inside a senstive region
          assert(S != MBB && (BBI->Orig != SBBI->Orig) && "Undetected loop");

          // !!TODO: Factor out the common logic between the three branches
          //          (when (S == Exit), (S == Return) and (S == Aligned))
          if (S == Exit) {

            // Create an empty block, if has not been created before, and
            // add CFG info and termination code. (A correct CFG is a precondition
            // for TII->insertBranch.)
            if (EmptyMBB == nullptr) {
              EmptyMBB = CreateMachineBasicBlock("empty", true);
              GetInfo(*EmptyMBB)->Orig = CloneMBB(EmptyMBB, false);
              // Update CFG
              EmptyMBB->addSuccessor(Exit);
              // Add termination code
              TII->insertBranch(*EmptyMBB, S, nullptr, {}, DebugLoc());

              R.Union.push_back(EmptyMBB);
            }

            // Update MBB
            assert((!BBI->IsReturn) && "Blocks with successors cannot return.");
            ReplaceSuccessor(MBB, S, EmptyMBB);

            // Create/update CF analysis for the new/changed blocks. This analysis
            //  is required by the alignment algo. Make sure to do this after
            //  updating the basic block's termination code and the CFG.
            //   (not sure if the CFG is actually used for this,
            //      but let's be conservative)
            ReAnalyzeControlFlow(
                *MBB); // TODO: Already done by ReplaceSuccessor
            ReAnalyzeControlFlow(*EmptyMBB); // Re-analyze because the empty MBB
            //  might be reused here.
            assert(GetInfo(*EmptyMBB)->FallThroughBB == nullptr);
          } else if (SBBI->IsReturn) {
            llvm_unreachable("Canonical CFG expected");
          } else if (SBBI->IsAligned) {
            // Create clone - The current successor has been aligned before.
            // Clone its original contents, if it has not been cloned before,
            //  and add CFG info and termination code. (A correct CFG is a
            //  precondition for TII->insertBranch.)
            assert(SBBI->Orig != nullptr);
            auto KV = Clones.find(SBBI->Orig);
            MachineBasicBlock *Clone = nullptr;
            if (KV != Clones.end()) {
              Clone = KV->second;
            } else {
              LLVM_DEBUG(dbgs() << "Cloning " << GetName(SBBI->BB) << "\n");
              Clone = CloneMBB(SBBI->Orig, true);
              Clones[SBBI->Orig] = Clone;
              for (auto SS : S->successors()) {
                Clone->addSuccessor(SS);
                // These successors will be cloned in turn during the next
                //  ComputeSuccessors call.
                // Ad-hoc pattern matching might prevent a cascade of cloning
              }

              // Update termination code
              // TODO: Fix copy-paste from
              //         MSP430NemesisDefenderPass::ReplaceSuccessor()::4
              TII->removeBranch(*Clone);
              if (SBBI->IsBranch) {
                if (SBBI->IsConditionalBranch) {
                  TII->insertBranch(*Clone, SBBI->TrueBB, SBBI->FalseBB,
                                    SBBI->BrCond, DebugLoc());
                  // Update taint analysis and containedness
                  //   - HasSecretDependentBranch is set during taint analysis
                  //   - IsPartOfSensitiveRegion is set during outer region analysis
                  GetInfo(*Clone)->HasSecretDependentBranch = true;
                  GetInfo(*Clone)->IsPartOfSensitiveRegion = true;
                } else {
                  TII->insertBranch(
                      *Clone, SBBI->TrueBB, nullptr, {}, DebugLoc());
                }
              } else {
                // A block with a successor cannot return
                assert(!SBBI->IsReturn);
                assert(SBBI->FallThroughBB != nullptr);
                TII->insertBranch(
                    *Clone, SBBI->FallThroughBB, nullptr, {}, DebugLoc());
              }

              R.Union.push_back(Clone);
            }

            // Update MBB
            ReplaceSuccessor(MBB, S, Clone);

            // Create/update CF analysis for the new/changed blocks. This
            //  analysis
            //  is required by the alignment algo. Make sure to do this after
            //  updating the basic block's termination code and the CFG.
            //   (not sure if the CFG is actually used for this,
            //      but let's be conservative)
            ReAnalyzeControlFlow(
                *MBB); // TODO: Already done by ReplaceSuccessor
            if (KV == Clones.end()) {
              AnalyzeControlFlow(*Clone);
            }
          } else {
            // Duplicates are not allowed in the Union
            if (Set.find(S) == Set.end()) {
              Set.insert(S);
              R.Union.push_back(S);
            }
          }
        }
      }
    }
  }

  // Check postcondition: There should be no duplicates in the Union.
  //
  // Remark: It is not possible to
  // use a std::set instead of a std::vector, because this would mean
  // that the order of insertion is not maintained. The order might be relevant
  // when effectively aligning the different blocks, because the order determines
  // the order in which the individual MBBs take the role as the reference block.
  std::set<MachineBasicBlock *> S(R.Union.begin(), R.Union.end());
  assert(S.size() == R.Union.size());

  return R;
}

#if 0
static void DumpMF(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << "==========================\n");
  for (auto &MBB : MF) {
    LLVM_DEBUG(dbgs() << MBB);
  }
  LLVM_DEBUG(dbgs() << "==========================\n");
}
#endif

void MSP430NemesisDefenderPass::AlignNonTerminatingInstructions(
    std::vector<MachineBasicBlock *> L) {
  assert(L.size() > 1);
  // Create two maps, mapping MBBs to
  //   1) instruction iterator (pointing to the beginning of the MBB)
  //   2) terminator iterator (pointing to branching code at end of MBB)
  // TODO: Map from MBB->getNumber -> MBB::iterator (and use more efficient map?)
  //         for this to work, blocks need to be correctly numbered which
  //         is currently not the case as ComputeSuccessors creates new MBBs
  std::map<MachineBasicBlock *, MachineBasicBlock::iterator> MII;
  std::map<MachineBasicBlock *, MachineBasicBlock::iterator> MTI;

  // 1) Initialize
  for (auto MBB : L) {
    // Don't add artifical blocks to BBAnalysis (by calling GetInfo) and,
    // consequently, don't mark artifical blocks as being aligned. This makes
    // sure that subsequent code safely ignores these blocks.
    // An example of an artifical block is the fingerprint block, which is used
    // to align a set of blocks with an previously aligned loop.
    if (MBB->getNumber() >= 0) {
      auto BBI = GetInfo(*MBB);
      assert(! BBI->IsAligned);
      BBI->IsAligned = true;
    }
    MII[MBB] = MBB->begin();
    MTI[MBB] = MBB->getFirstTerminator();
  }

  // 2) Align non-terminating instructions
  for (auto Ref : L) {

    LLVM_DEBUG(dbgs() << "Ref: " << GetName(Ref) << "\n");
    while (MII[Ref] != MTI[Ref]) {

      DebugLoc DL; // FIXME: Where to get DebugLoc from?

      // 2.1) First check if we are dealing with a call instruction in the
      //       current iteration.
      bool isCall = false;
      auto MBBI = L.begin();
      while ( (MBBI != L.end()) && (! isCall)) {
        auto BB = *MBBI++;
        if ((MII[BB] != BB->end()) && (MII[BB] != MTI[BB])) {
          auto &MI = *MII[BB];
          if (MI.isCall()) {

            // TODO: Reduce time-complexity (this is the third nested loop)
            for (auto BB2 : L) {
              if (BB2 != BB) {
                CompensateCall(MI, *BB2, MII[BB2]);
              }
            }
            MII[BB]++;

            isCall = true; // A call has been found. the Terminate loop.
          }
        }
      }

      // 2.2) Continue with the generic compensation logic for all other
      //       types of instruction when no call has been detected
      if (! isCall) {
        auto &RI = *MII[Ref]++;
        auto RIL = TII->getInstrLatency(nullptr, RI);
        LLVM_DEBUG(dbgs() << " " << RI << " (latency=" << RIL << ")\n");
        for (auto BB : L) {
          if (BB != Ref) {
            LLVM_DEBUG(dbgs() << "  " << GetName(BB) << ": ");
            if (MII[BB] == BB->end()) {
              LLVM_DEBUG(dbgs() << "insert nop (end-of-block)");
              CompensateInstr(RI, *BB, MII[BB]);
            } else if (MII[BB] == MTI[BB]) {
              LLVM_DEBUG(dbgs() << "insert nop (begin-of-branching-code)");
              CompensateInstr(RI, *BB, MII[BB]);
            } else {
              auto &MI = *MII[BB];
              auto MIL = TII->getInstrLatency(nullptr, MI);
              LLVM_DEBUG(dbgs() << MI << " (latency=" << MIL << "): ");
              if (RIL != MIL) {
                LLVM_DEBUG(dbgs() << "insert nop (non-matching-latency)");
                CompensateInstr(RI, *BB, MII[BB]);
              } else {
                LLVM_DEBUG(dbgs() << "latencies match");
                MII[BB]++;
              }
            }
            LLVM_DEBUG(dbgs() << "\n");
          }
        }
      }
    }

    assert(MII[Ref] == MTI[Ref]);
  }
}


// TODO: Generalize this implemenation. Now it is MSP430-specific and
//       only support two terminating instructions (according to the well-
//       formedness criterium).
// TODO: Optimize. It is not always necessary to assume that there are
//           always two terminating instructions...
void MSP430NemesisDefenderPass::AlignTerminatingInstructions(
    MachineBasicBlock *MBB) {
  auto T = MBB->getFirstTerminator();
  //LLVM_DEBUG(dbgs() << *MBB);
  //LLVM_DEBUG(dbgs() << *T);
  auto BBI = GetInfo(*MBB);
  switch (BBI->TerminatorCount) {
    case 0:
      assert(! BBI->IsBranch);
      assert(BBI->FallThroughBB != nullptr);
      BuildNOP2(*MBB, T, TII);
      BuildNOP2(*MBB, T, TII);
      break;
    case 1:
      if (BBI->IsConditionalBranch) {
        assert(BBI->FallThroughBB != nullptr);
        BuildNOP2(*MBB, T, TII);
        assert(TII->getInstrLatency(nullptr, *T++) == 2);
      }
      else if (BBI->IsReturn) {
        assert(TII->getInstrLatency(nullptr, *T) == 3);
        llvm_unreachable("Canonical CFG expected");
      }
      else {
        //LLVM_DEBUG(DumpMF(*MF));
        //LLVM_DEBUG(dbgs() << *MBB);
        assert(BBI->IsBranch);
        assert(BBI->FallThroughBB == nullptr);
        BuildNOP2(*MBB, T, TII);
        assert(TII->getInstrLatency(nullptr, *T++) == 2);
      }
      break;
    case 2:
      assert(BBI->IsConditionalBranch);
      assert(TII->getInstrLatency(nullptr, *T++) == 2);
      assert(TII->getInstrLatency(nullptr, *T++) == 2);
      break;
    default:
      llvm_unreachable("Invalid terminator count");
  }

  assert(T == MBB->end());
}

// Adds the definition with the highest id from Defs to the list of
//  candidate dependencies for the given instruction.
//  Returns true if a dependency has been added, false otherwise (empty Defs)
//
// PRE: The list of defs contains the instruction identifiers in MBB that
//   define the same register unit (RU)
// PRE: MI uses the thing that is defined
// PRE: Defs is sorted by increasing instruction id
bool MSP430NemesisDefenderPass::addDependency(MachineInstr *MI,
                                              MachineBasicBlock *MBB,
                                              std::vector<size_t> &Defs) {
  if (! Defs.empty()) {
    MBBInfo *BBI = GetInfo(*(MI->getParent()));
    auto IID = InstIds[MI];
    // The precondition states that the element in the back should corresponds
    //  to the instruction with the highest id.
    size_t DIID = Defs.back();
    assert(*(std::max_element(Defs.begin(), Defs.end())) == DIID);
    assert(DIID < MBB->size());
    MachineInstr *DMI = &*(std::next(MBB->begin(), DIID));
    BBI->Deps[IID].push_back(DMI);
#if 0
    LLVM_DEBUG(dbgs() << GetName(BBI->BB) << ":" << Id << " depends on "
               << GetName(MBB) << ":" << DIID << "\n");
#endif
    return true;
  }

  return false;
}

// Locates the instruction dependencies in a machine basic block of the given
// instruction MI with respect to the given register unit RU
// This method maintain a "visit list" to avoid endless recursion because of
// cycles in the CFG.
//  PRE: MI uses RU
//  PRE: MBB reaches MI
// TODO: Write unit test for ComputeDependencies
void MSP430NemesisDefenderPass::ComputeDependencies(
    MachineInstr *MI, size_t RU, MachineBasicBlock *MBB,
    SmallPtrSetImpl<MachineBasicBlock *> &Visited) {
  if (Visited.find(MBB) != Visited.end())
    return;

  Visited.insert(MBB);

  assert(MI != nullptr);
  assert(MBB != nullptr);
  assert(MI->getParent() != nullptr);
  MBBInfo *BBI = GetInfo(*(MI->getParent()));
  assert(BBI != nullptr);
  assert(InstIds.find(MI) != InstIds.end());
  auto IID = InstIds[MI];
  // Id is used to index BBI->Deps, assert it is within its bounds
  assert(IID < BBI->Deps.size());
  if (BBI->BB == MBB) {
    // If the MI's MBB defines the RU itself, register the def if the def site
    //  comes before MI. Don't look at the predecessors and leave early when
    //  this is the case.
    auto V = GetDefsBefore(BBI, RU, IID);
    if (addDependency(MI, MBB, V)) {
      // There is an instruction before MI in MI's MBB that defines RU
      return;
    }
  }

#if 0
  // TODO
  if (MBB->pred_size() == 0) {
    LLVM_DEBUG(dbgs() << "WARNING: Unitialized reg found\n");
  }
#endif

  for (MachineBasicBlock *PMBB : MBB->predecessors()) {
    auto PBBI = GetInfo(*PMBB);
    if (PMBB == MBB) {
      // Self-cycles can be safely ignored unless MBB is the MI's parent.
      if (BBI->BB == MBB) {
        if (GetDefsBefore(BBI, RU, IID).empty()) {
          // If addDependency returns true, then there is an instruction after
          //  MI in MI's MBB that defines RU.
          //  Since this is a cycle, this def reaches MI.
          auto V = GetDefsAfter(BBI, RU, IID);
          (void) addDependency(MI, MBB, V);
        }
      }
      // Don't recurse for self-cycles
    }
    else {
      assert(RU < PBBI->Defs.size());
      if (! addDependency(MI, PMBB, PBBI->Defs[RU])) {
        // Recursion terminates when the entry MBB has been reached
        //  since the entry MBB does not have any predecessors
        ComputeDependencies(MI, RU, PMBB, Visited);
      }
    }
  }
}

// The results are stored as dependencies between machine instructions which
//  is enough to implement the Nemesis defense.
void MSP430NemesisDefenderPass::ComputeReachingDefs() {
  // Compute reaching definitions
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    for (MachineInstr &MI : BBI.BB->instrs()) {
      for (MachineOperand &MO : MI.operands()) {
        // TODO: To be portable, deal with two-operand instructions whers
        //         a register can be both defined and used
        if (MO.isReg() && MO.isUse()) {
          assert(! MO.isDef());
          MCRegUnitIterator RUI(MO.getReg(), TRI);
          assert(RUI.isValid());
          auto RU = *RUI;
          ++RUI;
          assert(!RUI.isValid());
          assert(RU < TRI->getNumRegUnits());
          assert(RU < BBI.Defs.size());

          SmallPtrSet<MachineBasicBlock *, 4> Visited;
          ComputeDependencies(&MI, RU, BBI.BB, Visited);
        }
        else {
          // TODO: Do something similar for stack slots
          // if (MO.isFI()) ...
        }
      }
    }
  }
}

bool MSP430NemesisDefenderPass::IsSecretDependent(MachineInstr *MI) {
  return TaintInfo.find(MI) != TaintInfo.end();
}

bool MSP430NemesisDefenderPass::IsSecretDependent(MBBInfo *BBI) {
  return BBI->HasSecretDependentBranch;
}

// Marks the given machine instruction as tainted
void MSP430NemesisDefenderPass::Taint(MachineInstr * MI) {
  TaintInfo.insert(MI);

  //LLVM_DEBUG(dbgs() << GetName(MI->getParent()) << ": Tainting " << *MI);

  if (MI->isConditionalBranch()) {
    assert(MI->getParent() != nullptr);
    auto L = MLI->getLoopFor(MI->getParent());
    /* Loop latches are treated differently than ordinary branches and are not 
     *  considered "ordinary" secret dependent branches.
     */
    if (L == nullptr || (! L->isLoopLatch(MI->getParent()))) {
      auto BBI = GetInfo(*MI->getParent());
      BBI->HasSecretDependentBranch = true;
    }
  }
}

// An instruction I is part of a sensitive region S if
//   - the entry node of S is a predecessor of I's parent
//   - the exit node of S post-dominates I
//
// TODO: OPTIMIZE
//        - Avoid checking this again for every instruction in a block !
//        - Are there better ways to compute this information ?
//           (is it possible to compute MBBInfo::IsPartOfSensitiveRegion earlier
//             and use the result of that analysis (if this is the case,
//             this method only needs to check wether MI's parent's BBInfo
//             has this flag set to true)
bool
MSP430NemesisDefenderPass::IsPartOfSensitiveRegion(const MachineInstr *MI) {
  bool Result = false;

  auto MBB = MI->getParent();
  assert(MBB != nullptr);

  std::vector<MachineBasicBlock *> Preds(MBB->pred_begin(), MBB->pred_end());
  SmallPtrSet<MachineBasicBlock *, 4> Visited;

  while ( (! Preds.empty()) && (! Result) ) {
    auto PMBB = Preds.back();
    Preds.pop_back();
    if (Visited.find(PMBB) == Visited.end()) {
      Preds.insert(Preds.end(), PMBB->pred_begin(), PMBB->pred_end());
      Visited.insert(PMBB);
      auto BBI = GetInfo(*PMBB);
      if (BBI->HasSecretDependentBranch) {
        auto IPDom = (*MPDT)[PMBB]->getIDom();
        if (IPDom->getBlock() != nullptr) {
          if (MPDT->properlyDominates(IPDom->getBlock(), MBB)) {
            Result = true;
          }
        }
        else {
          // If we get here, the entry node of a sensitive region does not
          // have an immediate dominator. Conforming to the well-formedness
          // criterion, this is only possible if the sensitive region contains a
          // return node,
          //  (TODO: Verify this assumption)
          // in which case, the canonical exit node should act as
          // the immediate dominator. This makes the given instruction
          // part of the sensitive region because:
          //   (1) the secret-dependent node reaches the instruction and
          //   (2) the unique canonical exit node is the immediate dominator
          //       of the secret-dependent node and
          //   (3) the unique canonical exit node dominates every node in the
          //       CFG, including the parent of the given instruction

          // Create the canonical exit node when it has not been created before
          if (CanonicalExit == nullptr) {
            CanonicalExit = CreateMachineBasicBlock("exit", true);
            DebugLoc DL; // FIXME: Where to get DebugLoc from?
            BuildMI(CanonicalExit, DL, TII->get(MSP430::RET));
          }

          Result = true;
        }
      }
    }
  }

  return Result;
}

// Safe taint analysis (uses use-def chain, the result of the
//  reaching definitions analysis) to statically track confidential
//  information. At first, only analyze registers, and conservatively
//  consider the rest as secret. To be extended
//  to stack slots and global variables.
//
// During taint analysis, it is also determined whether the CFG needs to be
// canonicalized, i.e. transformed to a CFG with a single exit point (via calls
// to IsPartOfSensitiveRegion()). This analysis could not be done earlier,
// because there was no taint info yet.
//
// !TODO: Desperately needs optimization
//         - Implement this as a worklist algo (needs a def-use chain)
//         - Store the taint info in MBBInfo instead of a MF-level set?
void MSP430NemesisDefenderPass::PerformTaintAnalysis() {
  size_t N = 0;
  while (TaintInfo.size() > N) {
    N = TaintInfo.size();
    for (auto &MBB : *MF) {
      // Ignore the canonical exit node. Code asserts because the reaching def
      // analysis has not been peformed on this node. (Fix this?)
      if (&MBB == CanonicalExit)
        continue;

      //LLVM_DEBUG(dbgs() << MBB);
      auto BBI = GetInfo(MBB);
      for (auto &MI : MBB.instrs()) {
        auto IID = InstIds[&MI];
        assert(IID < BBI->Deps.size());
        if (TaintInfo.find(&MI) == TaintInfo.end()) {

          if (MI.isInlineAsm()) {
            llvm_unreachable("Inline assembly is not supported");
          }

          if (MI.isCall()) {
            // TODO: the call should only be marked tainted if one of the
            //       actual parameters is marked tainted
            Taint(&MI);
            //continue;
          }

          // Mark every conditional branch that is part of a sensitive region
          // senstive in turn.
          if (MI.isConditionalBranch()) {
            if (IsPartOfSensitiveRegion(&MI)) {
              Taint(&MI);
            }
          }

          for (auto &MO : MI.operands()) {
            if (TaintInfo.find(&MI) != TaintInfo.end()) {
              break;
            }
            // !TODO: Gradually support more cases, by adding more test
            //         cases
            switch (MO.getType()) {

              case MachineOperand::MO_Register         :
                if (MO.isUse()) {
                  for (auto DMI : BBI->Deps[IID]) {
                    if (IsSecretDependent(DMI)) {
                      Taint(&MI);
                    }
                  }
                }
                if (MO.isDef()) {
                  // Any assignment in a sensitive region taints the assigned
                  // variable.
                  if (IsPartOfSensitiveRegion(&MI)) {
                    Taint(&MI);
                  }
                }
                break;

              case MachineOperand::MO_Immediate        :
              case MachineOperand::MO_CImmediate       :
              case MachineOperand::MO_FPImmediate      :
                // Immediates don't leak information
                break;

              case MachineOperand::MO_MachineBasicBlock:
                // Used by (un)conditional jumps
                break;

                // TODO: Gradually support more operand types
              case MachineOperand::MO_ConstantPoolIndex:
              case MachineOperand::MO_ExternalSymbol   :
              case MachineOperand::MO_MCSymbol         :
              case MachineOperand::MO_FrameIndex       :
              case MachineOperand::MO_GlobalAddress    :
              case MachineOperand::MO_BlockAddress     :
              case MachineOperand::MO_TargetIndex      :
              case MachineOperand::MO_JumpTableIndex   :
              case MachineOperand::MO_RegisterMask     :
              case MachineOperand::MO_RegisterLiveOut  :
              case MachineOperand::MO_Metadata         :
              case MachineOperand::MO_CFIIndex         :
              case MachineOperand::MO_IntrinsicID      :
              case MachineOperand::MO_Predicate        :
              default:
#if 0
                LLVM_DEBUG(dbgs() << GetName(&MBB) << "\n");
                MI.dump();
#endif
                llvm_unreachable("Unknown operand type");
            }
          }
        }
      }
    }
  }
}

// Matchess the fork pattern. Typical for this pattern is that the branches 
// never join again.
//
//       EMBB
//      _/ \_
//      |   |
//      |  RBB1---> exit
//      |
//     LBB2
//
// !TODO: Generalize the fork pattern
bool MSP430NemesisDefenderPass::MatchFork(MBBInfo &EBBI) {
  MBBInfo *TBBI = GetInfo(*EBBI.TrueBB);
  MBBInfo *FBBI = GetInfo(*EBBI.FalseBB);

  assert(TBBI != FBBI);

  if (TBBI->IsReturn && FBBI->IsReturn) {
    EBBI.BClass = BCFork;
    auto &F = EBBI.BCInfo.Fork;
    F.LeftBB = TBBI->BB;
    F.RightBB = FBBI->BB;
    return true;
  }

  return false;
}

// Matches the triangle pattern.
//
//   Diverges on true edge:       Diverges on false edge:
//
//           EMBB                         EMBB
//           | \_                         | \_
//           |  |                         |  |
//           | TMBB                       | FMBB
//           |  /                         |  /
//           FMBB                         TMBB
//
// !TODO: Generalize the triangle pattern
bool MSP430NemesisDefenderPass::MatchTriangle(MBBInfo &EBBI, bool DivOnFalse) {
  MBBInfo *DivBBI = GetInfo(*EBBI.TrueBB);
  MBBInfo *JoinBBI = GetInfo(*EBBI.FalseBB);
  if (DivOnFalse) {
    DivBBI = GetInfo(*EBBI.FalseBB);
    JoinBBI = GetInfo(*EBBI.TrueBB);
  }

  if (DivBBI->Next == JoinBBI->BB) {
    EBBI.BClass = BCTriangle;
    auto &T = EBBI.BCInfo.Triangle;
    T.DivBB = DivBBI->BB;
    T.JoinBB = JoinBBI->BB;
    return true;
  }

  return false;
}

// Matches the diamond pattern.
//
//       EMBB
//      _/ \_
//      |   |
//    LMBB RMBB
//       \ /
//      JMBB
//
// !TODO: Generalize the triangle pattern
bool MSP430NemesisDefenderPass::MatchDiamond(MBBInfo &EBBI) {
  return false;
}

// The branch classifier considers only 'tainted' basic blocks as starting
//  points of the analysis. The result of this classification is input for
//  the alignment code generator.
void MSP430NemesisDefenderPass::ClassifyBranches() {
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    if (IsSecretDependent(&BBI)) {
      // Preconditions for matching functions
      assert(BBI.IsAnalyzable);
      assert(BBI.IsConditionalBranch);
      assert(BBI.TrueBB != nullptr);
      assert(BBI.FalseBB != nullptr);
      assert(BBI.TrueBB != BBI.FalseBB);
      if (!MatchFork(BBI))
      if (!MatchDiamond(BBI))
      if (!MatchTriangle(BBI, true))
      if (!MatchTriangle(BBI, false)) {
#if 0
        BBI.BB->dump();
        llvm_unreachable("TODO: Support more branch pattern classes");
#endif
      }
    }
  }
}

// ! TODO: Figure out if inserting (or removing) an element into an ilist does
//         not invalidate iterators or pointers to other elements in the list.
//
// Inserts a compensation instruction before the given position in the given
// MachineBasicBlock.
//
// TODO: Verify correctness of these nops (see also the note in the MSP430x1xx
//                                            Family User's guide).
//
void MSP430NemesisDefenderPass::CompensateInstr(const MachineInstr &MI,
                                                MachineBasicBlock &MBB,
                                                MachineBasicBlock::iterator I) {
  auto Latency = TII->getInstrLatency(nullptr, MI);

  // TODO: This code is MSP430-specific. It must be target-independent and
  //        should probably be described in the target description files.
  // TODO: What about non-deterministic Sancus crypto instructions?
  switch (Latency) {
    case 1: BuildNOP1(MBB, I, TII); break;
    case 2: BuildNOP2(MBB, I, TII); break;
    case 3: BuildNOP3(MBB, I, TII); break;
    case 4: BuildNOP4(MBB, I, TII); break;
    case 5: BuildNOP5(MBB, I, TII); break;
    case 6: BuildNOP6(MBB, I, TII); break;
    default:
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
      MI.dump();
#endif
      llvm_unreachable("Unexpected instruction latency");
  }
}

#define PREFIX_NEMDEF_SECURE "_nds_"
#define PREFIX_NEMDEF_DUMMY  "_ndd_"

// Compensates the call with a secure and dummy version of the callee
void MSP430NemesisDefenderPass::CompensateCall(const MachineInstr &Call,
                                               MachineBasicBlock &MBB,
                                               MachineBasicBlock::iterator I) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  assert(Call.isCall());

  std::string * N = new std::string(); // TODO: Fix mem leak ?

  const MachineOperand &MO = Call.getOperand(0);
  switch (Call.getOpcode()) {
    case MSP430::CALLi:
      switch (MO.getType()) {
        case MachineOperand::MO_ExternalSymbol:
          N->append(MO.getSymbolName());
          break;
        case MachineOperand::MO_GlobalAddress :
          N->append(MO.getGlobal()->getName());
          break;
        default:
          llvm_unreachable("Usupported machine operand");
      }

      // TODO: Avoid string manipulation
      if (N->find(PREFIX_NEMDEF_DUMMY) > 0) {
        if (N->find(PREFIX_NEMDEF_SECURE) == 0) {
          N->erase(0, strlen(PREFIX_NEMDEF_SECURE));
        }
        N->insert(0, PREFIX_NEMDEF_DUMMY);
      }

      BuildMI(MBB, I, DL, TII->get(MSP430::CALLi)).addExternalSymbol(N->c_str());
      break;

    case MSP430::CALLm:
    case MSP430::CALLn:
    case MSP430::CALLp:
    case MSP430::CALLr:
    default:
      LLVM_DEBUG(dbgs() << "OPCODE=" << Call.getOpcode() << "\n");
      llvm_unreachable("Usupported call");
  }
}

#if 0
bool
MSP430NemesisDefenderPass::IsEnryOfPattern(MBBInfo &BBI, BranchClass BClass) {
  return BBI.IsAnalyzable
    && BBI.IsConditionalBranch
    && BBI.HasSecretDependentBranch
    && (BBI.BClass == BClass);
}

// Inserts compensation instructions in Target at position TI for the
//  instructions starting from SI in Source
// Returns the target iterator TI
MachineBasicBlock::iterator
MSP430NemesisDefenderPass::AlignBlock(MachineBasicBlock &Source,
                                      MachineBasicBlock::iterator SI,
                                      MachineBasicBlock &Target,
                                      MachineBasicBlock::iterator TI) {
  while (SI != Source.end()) {
    if (! TII->isUnpredicatedTerminator(*SI)) { // TODO: replace by isTerminator()?
      CompensateInstr(*SI, Target, TI);
    }
    SI++;
  }
  return TI;
}

// Returns the position in MBB right before the branching code at the end
MachineBasicBlock::iterator MSP430NemesisDefenderPass::
GetPosBeforeBranchingCode(MachineBasicBlock *MBB) const {
  if (MBB->begin() == MBB->end())
    return MBB->begin();

  MachineBasicBlock::iterator MBBI = MBB->end();
  while (MBBI != MBB->begin()) {
    MBBI--;
    if (! MBBI->isDebugInstr()) {
      if (! TII->isUnpredicatedTerminator(*MBBI)) {
        break;
      }
    }
  }

  return ++MBBI;
}

void MSP430NemesisDefenderPass::AlignDiamond(MBBInfo &EBBI) {
}

void MSP430NemesisDefenderPass::AlignFork(MBBInfo &EBBI) {
  assert(IsEnryOfPattern(EBBI, BCFork));

  auto EBB = EBBI.BB;
  auto &F = EBBI.BCInfo.Fork;

  // Fork sanity checks
  assert(EBB->succ_size() == 2);
  assert(EBB->isSuccessor(F.LeftBB));
  assert(EBB->isSuccessor(F.RightBB));

  // Temporary assumptions
  assert(F.RightBB->isReturnBlock());
  assert(F.LeftBB->isReturnBlock());

  auto RBBI = AlignBlock(*F.LeftBB, F.LeftBB->begin(), *F.RightBB,
                         F.RightBB->begin());
  AlignBlock(*F.RightBB, RBBI, *F.LeftBB, GetPosBeforeBranchingCode(F.LeftBB));
}

void MSP430NemesisDefenderPass::AlignTriangle(MBBInfo &EBBI) {
  assert(IsEnryOfPattern(EBBI, BCTriangle));

  auto EBB = EBBI.BB;
  auto &T = EBBI.BCInfo.Triangle;

  // Triangle sanity checks
  assert(EBB->succ_size() == 2);
  assert(EBB->isSuccessor(T.DivBB));
  assert(EBB->isSuccessor(T.JoinBB));

  // Temporary assumptions
  assert(T.DivBB->succ_size() == 1);
  assert(T.DivBB->isSuccessor(T.JoinBB));

  // !TODO: Align the following branching code at the end of the entry
  //        block EBB:
  //                   JC TBB
  //                   J  FBB
  //      This is necessary because the unconditional branch is only executed
  //       for the false case

  // 1) Insert a new MBB
  auto NewBB = CreateMachineBasicBlock();
  MF->insert(MF->end(), NewBB);

  // 2) Update the CFG information (MBB.Successors and MBB.Predecessors)
  EBB->replaceSuccessor(T.JoinBB, NewBB);
  NewBB->addSuccessor(T.JoinBB);
  //NewBB->CorrectExtraCFGEdges();
  //EBB->CorrectExtraCFGEdges();

  // 3) Generate the actual alignment code
  TII->removeBranch(*T.DivBB); // Ignore the branching code at the end of DivBB
  for (auto &MI : *T.DivBB) {
    CompensateInstr(MI, *NewBB, NewBB->end());
  }

  // 4) Insert the necessary branching code at the end of the relevant MBBs
  //     to reflect the new CFG. To avoid generating alignment code for
  //     this branching code, make sure this is done after generating the
  //     alignment code.
  // TODO: The branch code must not perform possible "fallthrough-optimizations"
  //        for the Nemesis defense to work properly (check that this is the
  //        case)
  // TODO: Where to get the DebugLocs from?
  //
  //    4.1) EBB
  TII->removeBranch(*EBB);
  if (T.DivBB == EBBI.TrueBB) {
    TII->insertBranch(*EBB, T.DivBB, NewBB, EBBI.BrCond, DebugLoc());
  } else {
    TII->insertBranch(*EBB, NewBB, T.DivBB, EBBI.BrCond, DebugLoc());
  }
  //    4.2) NewBB
  TII->insertUnconditionalBranch(*NewBB, T.JoinBB, DebugLoc());

  //    4.3) DivBB
  //          Force an unconditional jump. Any possible branch code has been
  //          removed at the start of step 3).
  TII->insertUnconditionalBranch(*T.DivBB, T.JoinBB, DebugLoc());
}
#endif

// PRE: Entry is the entry point of a senstive branch
//
// The immediate post-dominator of Entry is the exit block of the sensitive
//  region.
MachineBasicBlock *
MSP430NemesisDefenderPass::GetExitOfSensitiveBranch(MachineBasicBlock *Entry) {
  assert(IsSecretDependent(GetInfo(*Entry)));
  assert((*MPDT).getNode(Entry) != nullptr);
  auto IPDom = (*MPDT)[Entry]->getIDom(); // Immediate post-dominator
  assert(IPDom->getBlock() != nullptr && "Canonical CFG expected");
  return IPDom->getBlock();
}

// Remark: Recomputes analysis passes
void MSP430NemesisDefenderPass::AlignContainedRegions(MachineLoop *Loop)
{
  auto Header = Loop->getHeader();
  assert(Header != nullptr);

  // !TODO: Factor out "for (auto &&KV : BBAnalysis)" for-loop from
  //         AlignSensitiveBranches() and this one
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    auto L = MLI->getLoopFor(BBI.BB);
    if (L != nullptr) {
      if (L == Loop) {
        if (IsSecretDependent(&BBI)) {
          // Deal with this "directly contained" sensitive branch
          AlignSensitiveBranch(BBI); // Recursive call (indirect)
        }
      } else if (L->getParentLoop() == Loop) {
        // Deal with this "directly contained" loop
        //LLVM_DEBUG(dbgs() << "Nested loop: " << GetName(L->getHeader()) << "\n");

        // According to the well-formedness criterion for loops, a loop
        // forms a SESE-region. This requires the following properties to hold:
        //  - there is a unique header
        //  - there is a unique latch
        //  - the loop header has one predecessor, the loop preheader
        //  - there is a unique exit, which is one of the two possible
        //    successors of the latch
        // This means we can just recurse here.
        // This could have been implemented differently (without recursion)
        // by iterating over all contained sensitive regions, not only the
        // directly contained ones. Intuitevely, it feels better to make a
        // distinction here as it is easier to extend when the well-formedness
        // criterion might be relaxed?
        AlignContainedRegions(L);
      }

      // Both AlignSensitiveBranch() and AlignContainedRegions() might
      //  give rise the recomputing the analysis passes
      // TODO: Make this less error prone and optimize this (see remark RedoAnalysisPasses)
      Loop = MLI->getLoopFor(Header);
      assert(Loop != nullptr);
      assert(Loop->getHeader() == Header);
    }
  }
}

static MachineLoop * 
getLoopFromHeader(MachineLoopInfo *MLI, MachineBasicBlock *Header) {
  auto L = MLI->getLoopFor(Header);
  assert(L != nullptr);
  assert(L->getHeader() != nullptr);
  assert(L->getHeader() == Header);
  return L;
}

// Aligns all MBBs with the given fingerprint
//
// Returns the list of successors of all sensitive regions, including the newly
//  ceated ones. This is required for the next call to ComputeSuccessors to
//  compute the successors based on the correct set.
//
// Remark: Recomputes analysis passes
//
// FIXME: Contains a recursive call that invalidates all pointers in 
//          analysis results. (see !!TODOS in body of this function)
//        (AlignFingerprint calls RedoAnalysisPasses...)
//
// TODO: Generalize to support arbitary regions (e.g. can be used as primitive
//     for ad-hoc, pattern-based optimizations (see notes))
std::vector<MachineBasicBlock *>
MSP430NemesisDefenderPass::AlignFingerprint(
    std::shared_ptr<Fingerprint> FP, std::vector<MachineBasicBlock *> MBBs) {

  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // Get necessary loop information
  assert(FP->LoopHeader != nullptr);
  // LTODO: In a generalized implemtation, it is necessary to check first that
  //   FP.LoopHeader <> nullptr
  auto FPLoop = getLoopFromHeader(MLI, FP->LoopHeader);
  auto LoopPreheader = FPLoop->getLoopPreheader();
  auto Header = FPLoop->getHeader();
  auto LoopLatch = FPLoop->getLoopLatch();
  auto ExitBlock = FPLoop->getExitBlock();

  auto BBIH = GetInfo(*Header);
  assert(BBIH->IsPartOfSensitiveRegion);
  assert(BBIH->IsLoopHeader);
  assert(BBIH->TripCount > 0);

  std::vector<MachineBasicBlock *> Result;

  // TODO: Optimize generated code for size, by 1) putting the generated loop in
  //        a separate block and 2) generating calls to this block

  // Start of loopification
  //   The generated code for loopification will be compensated for in the
  //    control-flow path of Loop (See code after this for-loop)
  LLVM_DEBUG(dbgs() << ">> START OF LOOPIFICATION (H=" 
      << GetName (FP->LoopHeader) << " TC=" << BBIH->TripCount << ")\n");

  // Pick an arbitrary register to act as the "induction register"
  unsigned IVar = MSP430::R10;

  // Align the artifical loop latch(es) with the "real loop latch", after adding
  //     instructions to
  //   - increment the induction variable
  //   - compare the induction variable with the trip count
  //
  // REMARK: The loop latch needs to be treated separately from the rest of
  //   the loop because of these two instructions. These instructions might
  //   give rise to compensating instructions in the "real loop latch", which is
  //   not the case for the other blocks of the loop.
  //
  // Do this once for all MMBs.
  auto TLatch = CreateMachineBasicBlock("temp-latch", false);
  BuildMI(TLatch, DL, TII->get(MSP430::ADD16ri), IVar).addReg(IVar).addImm(1);
  BuildMI(TLatch, DL, TII->get(MSP430::CMP16ri), IVar).addImm(BBIH->TripCount);
  // !!!LTODO: very ugly (find a better way to deal with this)
  bool AlreadyAligned = GetInfo(*LoopLatch)->IsAligned; // LTODO: UGLY
  if (!AlreadyAligned) {
    AlignNonTerminatingInstructions({LoopLatch, TLatch});
    // Because of the "branch compensating" operation, aligning with the
    // latch is an operation that is not idempotent.
    // This is important because the recursive nature of 
    // this function might result in invocating AlignNonTerminatingInstructions 
    // more than once for nested loops. (see region-loop-loop-tail.c with -O3)
    BuildBranchCompensator(*LoopLatch, LoopLatch->begin(), TII); // !!! LTODO: Document where this comes from
  }
  else {
    // Avoid compensating for extra jump over and over again (operation is not 
    //   idempotent)
    auto BBI = GetInfo(*LoopLatch);
    auto CLatch = CloneMBB(BBI->Orig, false);
    AlignNonTerminatingInstructions({CLatch, TLatch});
  }

  // After aligning the MBBs, the loop-header and the loop-exit need to be
  // compensated for the artifical loop-headers and artificial loop-exits
  // Therefore, LPH and LExit need to be visible in this scope.
  MachineBasicBlock *LPH = nullptr;
  MachineBasicBlock *LExit = nullptr;

  // First, align each of the MBBs
  for (auto MBB : MBBs) {
 
    assert(MBB->succ_size() == 1); // Guaranteed by ComputeSuccessors
    auto Succ = *MBB->succ_begin();

    LLVM_DEBUG(dbgs() << ">>>> LOOPIFY FOR " << GetName(FP->LoopHeader) 
        << " @ " << GetName(Succ) << "\n");

    LPH = MBB; /* MBB will be the loop preheader */
    auto LHeader = CreateMachineBasicBlock("loop-header", true);
    auto LLatch = CreateMachineBasicBlock("loop-latch", true);
    //GetInfo(*LHeader)->Orig = CloneMBB(EmptyMBB, false); // LTODO ?
    LExit = CreateMachineBasicBlock("loop-exit", true);

    // 1) - Add instructions to LPH that
    //      o push the current value of induction register on the stack
    //      o initialize the induction register
    //    - Set the loop header as its successor
    auto T = LPH->getFirstTerminator();
    assert(T != nullptr); // Guaranteed by ComputeSuccessors
    BuildMI(*LPH, T, DL, TII->get(MSP430::PUSH16r), IVar);
    BuildMI(*LPH, T, DL, TII->get(MSP430::MOV16ri), IVar).addImm(0);
    ReplaceSuccessor(LPH, Succ, LHeader);

    // 2) - Align the loop header with the loop fingerprint (modulo latch (!))
    //      The loop fingerprint is empty when the loop consists of a single
    //      MBB (in which case the MBB is both loop header and loop latch)
    //    - Set loop-latch as successor
    if (FP->Head->size() > 0) {
      // It is ok to pass FP->Head several times to the alignment function
      //  because LHeader will be empty each time at this point in the program.
      //  If this would not be the 
      //  case, FP->Head _could_ change after each invocation the alignment 
      //  function, in which case LHeader should be aligned against a copy of
      //  FP->Head.
      // LTODO: 
      //    1) Maybe it is a better idea to do it once outside of this loop
      // in a "temp-header" and copy its contents for every MBB in MBBs, similar
      // to the "temp-latch" block.
      //    2) Or maybe it is even better to just copy the contents of FP->Head
      //       here, since it exclusively exists of "dummy" instructions.
      assert(LHeader->size() == 0 && "Header not empty");
      AlignNonTerminatingInstructions({FP->Head, LHeader});
    }
    LHeader->addSuccessor(LLatch);
    TII->insertBranch(*LHeader, LLatch, nullptr, {}, DL); // !!LTODO: Compensate for this in "real loop"

    // 3) - Populate the loop latch (by copying instructions from temp-latch)
    //    - Connect loop-latch to loop-header and loop-exit by adding
    //       o a conditional jump to the loop header with the correct condition
    //       o an unconditional jump to the loop exit
    for (auto &MI : *TLatch) {
      MF->CloneMachineInstrBundle(*LLatch, LLatch->end(), MI);
    }
    LLatch->addSuccessor(LHeader);
    LLatch->addSuccessor(LExit);
    auto BrCond = MachineOperand::CreateImm(MSP430CC::CondCodes::COND_L);
    TII->insertBranch(*LLatch, LHeader, LExit, BrCond, DL);

    // 4) Restore the value of the induction register and connect the exit block
    //    to MBB
    BuildMI(LExit, DL, TII->get(MSP430::POP16r), IVar);
    LExit->addSuccessor(Succ);
    TII->insertBranch(*LExit, Succ, nullptr, {}, DL);

    // 5) Analyze control flow for newly created blocks
    AnalyzeControlFlow(*LPH);
    AnalyzeControlFlow(*LHeader);
    AnalyzeControlFlow(*LLatch);
    AnalyzeControlFlow(*LExit);

    // 6) Deal with nested loops (must be done _after_ analyzing the CF of
    //     the newly created blocks)
    for (auto &Tail : FP->Tail) {
      // Tail is a (Fingerprint, MBB) pair
      assert(Tail.first != nullptr);

#if 1 // !!!LTODO
        assert(LLatch->pred_size() == 1);
        auto Pred = *LLatch->pred_begin();
        auto EmptyMBB = CreateMachineBasicBlock("empty-for-loopif", true);
        //GetInfo(*EmptyMBB)->Orig = CloneMBB(EmptyMBB, false);
        ReplaceSuccessor(Pred, LLatch, EmptyMBB);
        EmptyMBB->addSuccessor(LLatch);
        TII->insertBranch(*EmptyMBB, LLatch, nullptr, {}, DebugLoc());
        AnalyzeControlFlow(*EmptyMBB);
#endif

      AlignFingerprint(Tail.first, {EmptyMBB});

      // Align with the rest (tail) of fingerprint
      // LTODO: Same remark here as for aligning FP->Head (see above)
      auto TailBB = CreateMachineBasicBlock("tail", true);
      assert(TailBB->size() == 0 && "Header not empty");
      AlignNonTerminatingInstructions({Tail.second, TailBB});

      assert(LLatch->pred_size() == 1);
      Pred = *LLatch->pred_begin(); // Should be exit block of nested loop
      assert(Pred->pred_size() == 1);
      auto PredPred = *Pred->pred_begin(); // Should be latch of nested loop

      // Sanity check: LHeader should be disconnnected from LLatch at this point
      assert(!LHeader->isSuccessor(*LLatch->pred_begin()));

#if 1
      // More santity checks: At this point in the program, the unique 
      //   predecessor of the latch should be the latch of another loop.
      assert(MLI->getLoopFor(Pred) != nullptr);
      auto L = getLoopFromHeader(MLI, LHeader);
      assert(MLI->getLoopFor(Pred) == L);
      assert(MLI->getLoopFor(PredPred) != nullptr);
      assert(MLI->getLoopFor(PredPred)->getLoopLatch() != nullptr);
      assert(MLI->getLoopFor(PredPred)->getLoopLatch() == PredPred);
#endif

      // Insert TailBB between Pred and LLatch
      ReplaceSuccessor(Pred, LLatch, TailBB);
      TailBB->addSuccessor(LLatch);
      TII->insertBranch(*TailBB, LLatch, nullptr, {}, DL); // !!!LTODO: Compensate for this in "real loop"

      AnalyzeControlFlow(*TailBB);
    }

#if 0
    // 7) Updated IsAligned information:
    //  These MBBs will be aligned at the end of the current function
    //  invocation.
    GetInfo(*PH)->IsAligned = true;
    GetInfo(*LExit)->IsAligned = true;
    GetInfo(*Succ)->IsAligned = true;
#endif

    // Make sure that ComputeSuccessors computes the correct successor in the
    //  current control-flow path (starting from the newly created exit node).
    Result.push_back(LExit);

    // CHECK POSTCONDITION:
    // -> The latch should end with a conditional jump, followed by an 
    // unconditional jump
    assert(std::distance(LLatch->terminators().begin(),
                         LLatch->terminators().end()) == 2);
  }

  // Compensate for the loopification in the real loop
  //  by creating a new loop-preheader and loop-exit blocks
  // (LTODO: OPTIMIZE
  //     This can probably be avoided, by creating a temp-pheader and a
  //      temp-exit similar to the temp-latch above...)
  if (! AlreadyAligned) {
    auto NewLoopPreheader = CreateMachineBasicBlock("loop-pheader", true);
    assert(LPH != nullptr); //  Any PH will do as a reference, so let's take the last one
    //GetInfo(*PH)->IsAligned = false; // Avoid assert from begin triggered
    AlignNonTerminatingInstructions({NewLoopPreheader, LPH});
    NewLoopPreheader->addSuccessor(Header);
    TII->insertBranch(*NewLoopPreheader, Header, nullptr, {}, DL);
    ReplaceSuccessor(LoopPreheader, Header, NewLoopPreheader);

    auto NewExitBlock = CreateMachineBasicBlock("loop-exit", true);
    assert(LExit != nullptr); //  Any LExit will do as a reference, so let's take the last one
    //GetInfo(*LExit)->IsAligned = false; // Avoid assert from being triggered
    AlignNonTerminatingInstructions({NewExitBlock, LExit});
    NewExitBlock->addSuccessor(ExitBlock);
    TII->insertBranch(*NewExitBlock, ExitBlock, nullptr, {}, DL);
    ReplaceSuccessor(LoopLatch, ExitBlock, NewExitBlock);

    // Make sure the successor of the loop will be computed correctly by
    //  the next call to ComputeSuccessors...
    Result.push_back(NewExitBlock);

    // Analyze CF for newly created blocks
    AnalyzeControlFlow(*NewLoopPreheader);
    AnalyzeControlFlow(*NewExitBlock);
  }

  LLVM_DEBUG(dbgs() << ">> END OF LOOPIFICATION (" << GetName (FP->LoopHeader) 
      << ")\n");

  // CHECK POSTCONDITION:
  // -> The latch should end with a conditional jump, followed by an unconditional
  //     jump
  assert(std::distance(LoopLatch->terminators().begin(),
                       LoopLatch->terminators().end()) == 2);

  RedoAnalysisPasses(); // TODO: Optimize (see remark at function definition)

  return Result;
}

// AlignSensitiveLoop peforms the following actions:
//  1) aligns all sensitive regions for which the "closest" loop is 'this' loop
//  2) Aligns all MBBs with the aligned loop region
//
//  It recursively deals with nested loops.
//
// Returns the list of successors of all the loop regions, including the newly
//  ceated ones. This is required for the next call to ComputeSuccessors to
//  compute the successors based on the correct set.
//
// Remark: AlignSensitiveLoop is mutually recursive with AlignSensitiveBranch
//
// Remark: Recomputes analysis passes
std::vector<MachineBasicBlock *>
MSP430NemesisDefenderPass::AlignSensitiveLoop(MachineLoop *Loop,
                                           std::vector<MachineBasicBlock *> MBBs) {
  // Get necessary loop information
  // AlignContainedRegions (below) and loopification (below) invalidates loop
  // analysis. Also, loop analysis seems to depend on CFG and/or termination
  // code.
  auto LoopPreheader = Loop->getLoopPreheader();
  auto Header = Loop->getHeader();
  auto LoopLatch = Loop->getLoopLatch();
  auto ExitBlock = Loop->getExitBlock();

  // Verify wel-formedness criterion
  assert(LoopPreheader != nullptr);
  assert(Header != nullptr);
  assert(LoopLatch != nullptr);
  assert(ExitBlock != nullptr);
  assert(LoopLatch->isSuccessor(ExitBlock));
  assert(*LoopPreheader->succ_begin() == Header);

  // First align the contained regions (no straigh-line code) of this loop,
  //  because an aligned loop region is a precondition for GetFingerprint.
  AlignContainedRegions(Loop); // Recomputes analyses passes
  Loop = MLI->getLoopFor(Header);
  assert(Loop != nullptr); // Header should still be part of a loop
  assert(Header == Loop->getHeader());

  // Sanity check (AlignContainedRegions might change the CFG, but the
  //               special loop blocks should not change)
  assert(LoopPreheader == Loop->getLoopPreheader());
  assert(LoopLatch == Loop->getLoopLatch());
  assert(ExitBlock == Loop->getExitBlock());

  // GeFingerprint depends on a correct loop analysis (see comments above)
  return AlignFingerprint(GetFingerprint(Loop), MBBs);
}

void MSP430NemesisDefenderPass::RedoAnalysisPasses() {
  // !LTODO: It might be better to "maintain" the Loop information and the
  //   dominator tree instead of redoing the complete analysis over and over again
  //    (see for example MLI::addBasicBlockToLoop() which seems to exist for this)
  // TODO! How to enforce a re-anlysis of MLI and all passes it depends on in
  //        a cleaner and more automated and less hardcoded way
  //MF->viewCFG();
  MDT->runOnMachineFunction(*MF); // MLI depends on this
  //MDT->dump();
  MLI->runOnMachineFunction(*MF); // !!TODO: Is this the right way to do this?
}

// Aligns the sensitive branch that starts with BBI.BB
//
// When this function returns,
//   the sensitive branch defined by (BBI.BB, ExitOfSR) will be secure. All 
//   possible paths in the region will have same fingerprint. This means that
//   the complete region will be compensated for 
//     - unbalanced non-terminating instructions
//     - unbalanced terminating instructions
//     - unbalanced two-way branches
// Consequently, GetFingerprint() will return the correct fingerprint.
//
// Remark: Recomputes analysis passes
void MSP430NemesisDefenderPass::AlignSensitiveBranch(MBBInfo &BBI) {
#if 0
  switch (BBI.BClass) {
    case BCFork:
      AlignFork(BBI);
      break;
    case BCDiamond:
      AlignDiamond(BBI);
      break;
    case BCTriangle:
      AlignTriangle(BBI);
      break;
    case BCNotClassified:
      // ! TODO Enable this again
      llvm_unreachable("Unclassfied branch pattern");
      break;
    default:
      llvm_unreachable("Unknown branch pattern");
  }
#endif

  auto ExitOfSR = GetExitOfSensitiveBranch(BBI.BB);
  LLVM_DEBUG(dbgs() << "=== Align sensitive branch (" << GetName(BBI.BB) << ", "
                    << GetName(ExitOfSR) << ") ===\n");

  assert(!BBI.IsAligned);

  std::vector<MachineBasicBlock *> MBBs; // Keep track of aligned blocks

  // 1) Align non-terminating instructions
  Successors Succs;
  Succs = ComputeSuccessors({BBI.BB}, ExitOfSR);
  while (!Succs.Union.empty()) {
    // TODO: Make sure this loop terminates
    if (Succs.Loop == nullptr) {
      assert(Succs.Union.size() > 1);
      AlignNonTerminatingInstructions(Succs.Union);
      std::copy(Succs.Union.begin(), Succs.Union.end(), std::back_inserter(MBBs));
      Succs = ComputeSuccessors(Succs.Union, ExitOfSR);
    }
    else {
      // A loop has been detected by ComputeSuccessors, deal with it first
      auto Union = AlignSensitiveLoop(Succs.Loop, Succs.Union);
      Succs = ComputeSuccessors(Union, ExitOfSR);
    }
  }

  // 2) Align terminating instructions
  for (auto MBB : MBBs) {
    MBBInfo *BBI = GetInfo(*MBB);

    assert(BBI->IsAligned);

    // Aligning the termination instructions should be done after aligning
    // the non-termination instructions of all MBBs in the sensitive branch.
    // This is because the termination code can still change when aligning
    // one of the successor blocks (e.g. when an empty block is inserted).
    AlignTerminatingInstructions(BBI->BB);
  }

  // 3) Align two-way branches
  MBBs.push_back(BBI.BB); // Don't forget to include the entry block
  for (auto MBB : MBBs) {
    MBBInfo *BBI = GetInfo(*MBB);

    // Aligning two-way branches should be done after aligning the
    // non-terminating instructions because the instruction that gets inserted
    // in the true path, to compensate for the JMP in the false path,
    // does not have to be taken into account when aligning the MBBs at the
    // same level (See AlignBlocks), because technically this compensating 
    // instruction belongs the previous MBB (or you could say that it is an 
    // artifact of how two-way branches need to be represented in MIR).
    if (BBI->HasSecretDependentBranch) {
      if (BBI->IsConditionalBranch && (BBI->FallThroughBB == nullptr)) {
        assert(BBI->TerminatorCount == 2);
        AlignTwoWayBranch(*MBB);
      }
    }
  }

  LLVM_DEBUG(dbgs() << "=== Done ===\n");

  RedoAnalysisPasses(); // TODO: Optimize (see remark at function definition)
}

void MSP430NemesisDefenderPass::AnalyzeLoops() {
  for (auto &KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    if (BBI.IsPartOfSensitiveRegion) {
      auto L = MLI->getLoopFor(BBI.BB);
      if ( (L != nullptr) && (BBI.BB == L->getHeader())) {
        // Verify wel-formedness criterion for loops
        // LTODO: check all constraints
        assert(L->getLoopPreheader() != nullptr);
        assert(L->getHeader() != nullptr);
        assert(L->getLoopLatch() != nullptr);
        assert(L->getExitBlock() != nullptr);
        assert(L->getLoopLatch()->isSuccessor(L->getExitBlock()));
        assert(*L->getLoopPreheader()->succ_begin() == L->getHeader());

        // LTODO: Document this better
        // Register that this block is the header of a loop.
        // In the nemdef pass, loops are represented by their header-MBB, a 
        // property for loops that is invariant in this pass. (The preheader 
        //  and exit blocks can be different before and after the 
        //  transformation.)
        // Loop data structures retured by MLI are invalidated when 
        //  loop analysis is recomputed. For this reason, it is not safe
        //   to store loop pointers in nemdef data structures since they
        //    can become dangling.
        // The nemdef transformation does not always preserves the
        //  well-formedness criterion. ComputeTripCount for example
        //  expects that the initialization of the induction register
        //  occurs in the preheader block. However, nemdef might introduce
        //  an new "artificial" loop between the preheader of a 
        //  well-formed loop and the actual loop 
        //   (see nemdef-loop-loop-tail-O3 for example)
        BBI.IsLoopHeader = true;

        // Compute the loop trip count. According to the well-formedness 
        // criterion this should be statically computable.
        BBI.TripCount = GetLoopTripCount(L);
      }
    }
  }
}

// POST: A sensitive branch is an outer sensitive branch iff
//        its entry MBB's BBInfo has its IsPartOfSensitiveRegion flag not set
// TODO: Verify correctness of this (unit tests)
//        especially how this functions deals with loops in the CFG and
//        with overlapping regions
void MSP430NemesisDefenderPass::DetectOuterSensitiveBranches() {

  std::vector<std::pair<MachineBasicBlock *, MachineBasicBlock *>> MBBs = {
      {EntryBBI->BB, nullptr}
  };

  std::set<MachineBasicBlock *> Visited;

  Visited.insert(EntryBBI->BB);
  while (! MBBs.empty()) {
    MachineBasicBlock *MBB, *endOfCurrentRegion;
    std::tie(MBB, endOfCurrentRegion) = MBBs.back();
    MBBs.pop_back();

    if (endOfCurrentRegion == nullptr) {
      if (IsSecretDependent(GetInfo(*MBB))) {
        endOfCurrentRegion = GetExitOfSensitiveBranch(MBB);
      }
    }

    for (auto S : MBB->successors()) {
      // Avoid endless loop when CFG contains a loop
      if (Visited.find(S) == Visited.end()) {
        Visited.insert(S);
        if ( (endOfCurrentRegion == nullptr) || (S == endOfCurrentRegion) ) {
          MBBs.push_back({S, nullptr});
        } else {
          MBBs.push_back({S, endOfCurrentRegion});
          //LLVM_DEBUG(dbgs() << GetName(S) << " is part of sensitive region\n");
          GetInfo(*S)->IsPartOfSensitiveRegion = true;
        }
      }
    }
  }
}

// Replaces the call to a call of the secure version of the callee
void MSP430NemesisDefenderPass::SecureCall(MachineInstr &Call) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  assert(Call.isCall());

  std::string * N = new std::string(); // TODO: Fix mem leak ?

  MachineOperand &MO = Call.getOperand(0);
  switch (Call.getOpcode()) {
    case MSP430::CALLi:

      switch (MO.getType()) {
        case MachineOperand::MO_ExternalSymbol:
          N->append(MO.getSymbolName());
          break;
        case MachineOperand::MO_GlobalAddress :
          N->append(MO.getGlobal()->getName());
          break;
        default:
          llvm_unreachable("Usupported machine operand");
      }

      // TODO: Avoid string manipulation
      if (N->find(PREFIX_NEMDEF_SECURE) > 0) {
        if (N->find(PREFIX_NEMDEF_DUMMY) > 0) {
          N->insert(0, PREFIX_NEMDEF_SECURE);
          MO.ChangeToES(N->c_str());
        }
      }

      break;

    case MSP430::CALLm:
    case MSP430::CALLn:
    case MSP430::CALLp:
    case MSP430::CALLr:
    default:
      LLVM_DEBUG(dbgs() << "OPCODE=" << Call.getOpcode() << "\n");
      llvm_unreachable("Usupported call");
  }
}

void MSP430NemesisDefenderPass::SecureCalls() {
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    if (BBI.IsPartOfSensitiveRegion) {
      for (auto &MI : *BBI.BB) {
        if (MI.isCall()) {
          SecureCall(MI);
        }
      }
    }
  }
}

// For every pattern, a corresponding alignator exists
void MSP430NemesisDefenderPass::AlignSensitiveBranches() {
  //MF->viewCFG();

  // Keep track of original contents to be able to clone the original
  // when necessary.
  // !!TODO: When keeping track of the original, keep track of
  //          the original successors as well !!
  // TODO: Optimize - There is no need to keep a copy of the original
  //                   contents for every MBB
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    BBI.Orig = CloneMBB(BBI.BB, false);
    assert(BBI.Orig != nullptr);
  }

  // 1) Align outer sensitive branches
  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
    // BBI.IsPartOfSensitiveRegion makes sure that only
    // outer sensitive branches will be considered here
    // (Note that this is not the same as "overlapping senstive regions")
    if (IsSecretDependent(&BBI) && (! BBI.IsPartOfSensitiveRegion) ) {
      AlignSensitiveBranch(BBI);
    }
  }
}

#if 0
void MSP430NemesisDefenderPass::DumpDebugInfo() {
  LLVM_DEBUG(dbgs() << "============== INFO ====================\n");
  for (auto &MBB: *MF) {
    auto BBI = GetInfo(MBB);
    LLVM_DEBUG(dbgs() << GetName(&MBB)
        << " TerminatorCount=" << BBI->TerminatorCount
        << "\n");
  }
  LLVM_DEBUG(dbgs() << "========================================\n");
}
#endif

void MSP430NemesisDefenderPass::DumpCFG() {
  // TODO: Compare with the CFG build by LLVM, not applying the
  //        transformations of this pass (graphs should be isomorphic)
#if 1
  MF->viewCFG();
#else
  MF->viewCFGOnly();
#endif

  int FD;
  auto FN = createGraphFilename(MF->getName(), FD);
  raw_fd_ostream O(FD, /*shouldClose=*/ true);
  // TODO: Use GraphWriter

  O << "digraph " << MF->getName() << "{\n";

  for (auto &&KV : BBAnalysis) {
    MBBInfo &BBI = KV.second;
#if 0
    if (BBI.IsEntry) {
      O << GetName(BBI.BB) << " [color=green];\n";
    }
#endif

    if (BBI.HasSecretDependentBranch) {
      O << GetName(BBI.BB) << " [color=red];\n";
    }

    if (BBI.IsAnalyzable) {
      if (BBI.IsBranch) {
        assert(BBI.TerminatorCount > 0);
        if (BBI.TrueBB) {
          O << GetName(BBI.BB) << " ->" << GetName(BBI.TrueBB) << ";\n";
        }
        if (BBI.FalseBB) {
          O << GetName(BBI.BB) << " ->" << GetName(BBI.FalseBB) << ";\n";
        }
      }
      if (BBI.TerminatorCount == 0) {
        assert(!BBI.IsBranch);
        assert(BBI.FallThroughBB != nullptr);
        O << GetName(BBI.BB) << " ->" << GetName(BBI.FallThroughBB) << ";\n";

      }
    } else {
      // Mark as un-analyzable
      O << GetName(BBI.BB) << " [color=purple];\n";
    }
  }

  O << "}\n";

  DisplayGraph(FN, false, GraphProgram::DOT);
}

void MSP430NemesisDefenderPass::PrepareAnalysis() {
  MF->RenumberBlocks();
#if 0  // Re-enable when BBAnalysis is a vector
  BBAnalysis.resize(MF->getNumBlockIDs());
#endif

  // Create dummy machine instructions at the beginning of the entry MBB to
  //  represent the CC defs. Add them to the taint set when their corresponding
  //  argument is marked "_secret". This allows for a uniform and therefore
  //  simpler taint analysis implementation.
  // TODO: Code is MSP430-specific and should be platform independent
  //        -> Possible use the generated info from the TableGen CallingConv 
  //            backend?
  // TODO: Get rid of Reg++
  auto &MBB = *GetEntryMBB(MF);
  auto MBBI = MBB.begin();
  auto DL   = MBBI->getDebugLoc();
  int Reg   = MSP430::R12;
  // TODO: Stop after 4 iterations (for MSP430 at least)
  for (auto &Arg : MF->getFunction().args()) {
    auto MI = BuildMI(MBB, MBBI, DL, TII->get(MSP430::MOV16ri), Reg++).addImm(0);
    if (IsSecret(Arg)) {
      TaintInfo.insert(MI);
    }
  }
}

void MSP430NemesisDefenderPass::FinishAnalysis() {
  // Remove the dummy machine instructions at the beginning of the entry MBB,
  //  representing the CC defs
  auto MBB = GetEntryMBB(MF);
  auto MBBI = MBB->begin();
  for (size_t i=0; i<MF->getFunction().arg_size(); i++) {
    auto MI = &*MBBI++;
    MBB->remove(MI);
  }
}

// Canonicalizes the CFG when necessary (determined during taint analysis).
// The canonicalization step transforms a CFG with multiple exit points into
// one where there is only one.
// TODO: Optimize
//        Now every return block is replaced with a branch block
//        while this is only required for return blocks in senstive regions
void MSP430NemesisDefenderPass::CanonicalizeCFG() {
  if (CanonicalExit != nullptr) {

    LLVM_DEBUG(dbgs() << "Canonicalize CFG\n");

    for (auto &MBB : *MF) {
      if (&MBB == CanonicalExit)
        continue;

      if (GetInfo(MBB)->IsReturn) {
        // Remove the return instruction, update CFG, termination code and
        // BBAnalysis
        DebugLoc DL; // FIXME: Where to get DebugLoc from?
        RemoveTerminationCode(MBB);
        MBB.addSuccessor(CanonicalExit);
        TII->insertBranch(MBB, CanonicalExit, nullptr, {}, DL);
        ReAnalyzeControlFlow(MBB);
      }
    }

    AnalyzeControlFlow(*CanonicalExit);

    // Don't forget to rebuild the post-dominator tree
    MPDT->runOnMachineFunction(*MF); // !!TODO: Is this the right way to do this?

    LLVM_DEBUG(dbgs() << "Canonicalization done\n");
  }
}

bool MSP430NemesisDefenderPass::runOnMachineFunction(MachineFunction &MF) {
  if (skipFunction(MF.getFunction()))
    return false;
  if (!Enable)
    return false;

  LLVM_DEBUG(dbgs() << "********** " << getPassName() << " : " << MF.getName()
                    << "**********\n");

  bool Changed = false;
  const TargetSubtargetInfo &STI = MF.getSubtarget();
  this->MF = &MF;
  //TII=static_cast<const MSP430InstrInfo *>(MF->getSubtarget().getInstrInfo());
  //TLI = STI.getTargetLowering();
  MRI = &MF.getRegInfo();
  TII = STI.getInstrInfo();
  TRI = STI.getRegisterInfo();
  MLI = &getAnalysis<MachineLoopInfo>();

  if (!TII) return false;

  MDT = &getAnalysis<MachineDominatorTree>();
  MPDT = &getAnalysis<MachinePostDominatorTree>();

  // TODO: assert(!MRI->isSSA());

  if (EmitCFG) {
    MF.viewCFGOnly(); // Dump unhardened CFG before any possible changes
  }

  // Perform analysis
  PrepareAnalysis();
  AnalyzeControlFlow();
  VerifyControlFlowAnalysis();
  ComputeReachingDefs();

  PerformTaintAnalysis();
  ClassifyBranches();
  FinishAnalysis();

  // Canonicalize CFG, if needed
  CanonicalizeCFG();

  if (EmitCFG) {
    MF.viewCFGOnly(); // Dump after canonicalization, before hardening
  }

  // Analyses performed after canonicalization
  DetectOuterSensitiveBranches();
  AnalyzeLoops();

  // Generate hardening code
  //DumpDebugInfo();
  SecureCalls();
  AlignSensitiveBranches();
  //DumpDebugInfo();

  if (EmitCFG) {
    DumpCFG(); // Dump after hardening CFG
  }

  return Changed;
}

void MSP430NemesisDefenderPass::releaseMemory() {
  BBAnalysis.clear(); // TODO: Does this also clear Defs and Deps?
  InstIds.clear();
  TaintInfo.clear();
}

#if 0
INITIALIZE_PASS_BEGIN(MSP430NemesisDefenderPass, DEBUG_TYPE,
                      "X86 cmov Conversion", false, false)
INITIALIZE_PASS_DEPENDENCY(MachineLoopInfo)
INITIALIZE_PASS_END(MSP430NemesisDefenderPass, DEBUG_TYPE,
                    "X86 cmov Conversion", false, false)
#endif
static RegisterPass<MSP430NemesisDefenderPass> X(DEBUG_TYPE,
                                                 "MSP430 Nemesis Defender Pass",
                                                 false /* Only looks at CFG */,
                                                 false /* Analysis Pass */);


FunctionPass *llvm::createMSP430NemesisDefenderPass() {
  return new MSP430NemesisDefenderPass();
}
