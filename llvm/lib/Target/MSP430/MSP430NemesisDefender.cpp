#include <memory>
#include <fstream>

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
static cl::opt<bool>
    SaveCFG(DEBUG_TYPE "-save-cfg",
            cl::desc("Save control flow graph (GraphViz)"),
            cl::init(false), cl::Hidden);

// TODO: Give credit to IfConversion pass?
//         (only if idea of branch-patterns is used)
// TODO: Refactor: Decompose in several classes
//        (sensitivity analysis, shape matchers,...)

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
    bool IsLoopLatch                : 1;
    bool IsCanonicalLoopBlock       : 1;
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

#if 0
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
#endif

    MBBInfo() : IsDone(false), IsAligned(false), IsAnalyzable(false),
      IsBranch(false), IsConditionalBranch(false),
      IsPartOfSensitiveRegion(false), IsLoopHeader(false), IsLoopLatch(false),
      IsCanonicalLoopBlock(false),
      HasSecretDependentBranch(false),
      IsEntry(false), IsReturn(false) {}
  };

  // Set to true when the sensitivity analysis detected at least one
  // secret dependent branch
  bool HasSecretDependentBranch = false;

  // Return type of ComputeSuccessors
  struct Successors {
    std::vector<MachineBasicBlock *> Succs;
    MachineLoop *Loop; // ! TODO: Beware of dangling pointers
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
  /// The set of sensitive instructions
  SmallPtrSet<const MachineInstr *, 10> SensitivityInfo;

  MachineFunction *MF;
  // The sensitivity analysis procedure determines whether canonicalization is
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

  std::vector<MachineBasicBlock *> GetFingerprint(MachineLoop *L);
  void BuildFingerprint(MachineLoop *L, std::vector<MachineBasicBlock *> &FP);

  // Exit is the "join block" or the "point of convergence" of the originating
  //  sensitive region.
  Successors
  ComputeSuccessors(std::vector<MachineBasicBlock *> L, MachineBasicBlock *Exit);

  void AlignNonTerminatingInstructions(std::vector<MachineBasicBlock *> L);
  void CanonicalizeTerminatingInstructions(MachineBasicBlock *MBB);
  void AlignTwoWayBranch(MachineBasicBlock &MBB);

  // Returns information about sensitivity of machine instructions and basic
  //  block info.
  bool IsSecretDependent(MachineInstr *MI);
  bool IsSecretDependent(MBBInfo *BBI);
  bool IsTwoWayBranch(MBBInfo *BBI);

  void PrepareAnalysis();
  void FinishAnalysis();
  void CanonicalizeCFG();

  bool addDependency(MachineInstr *MI, MachineBasicBlock *MBB,
                     std::vector<size_t> &Defs);

  // RU is a register unit
  void ComputeDependencies(MachineInstr *MI, size_t RU, MachineBasicBlock *MBB,
                           SmallPtrSetImpl<MachineBasicBlock *> &Visited);

  void RegisterDefs(MBBInfo &BBI);

  void CompensateInstr(const MachineInstr &MI, MachineBasicBlock &MBB,
                       MachineBasicBlock::iterator MBBI);
  void CompensateCall(const MachineInstr &Call, MachineBasicBlock &MBB,
                      MachineBasicBlock::iterator MBBI);
  void SecureCall(MachineInstr &Call);

#if 0
  MachineBasicBlock::iterator GetPosBeforeBranchingCode(MachineBasicBlock *MBB)
  const;

  bool MatchFork(MBBInfo &EBBI);
  bool MatchDiamond(MBBInfo &EBBI);
  bool MatchTriangle(MBBInfo &EBBI, bool DivOnFalse);

  MachineBasicBlock::iterator AlignBlock(MachineBasicBlock &Source,
                                         MachineBasicBlock::iterator SI,
                                         MachineBasicBlock &Target,
                                         MachineBasicBlock::iterator TI);

  bool IsEnryOfPattern(MBBInfo &BBI, BranchClass BClass);

  void AlignTriangle(MBBInfo &EBBI);
  void AlignDiamond(MBBInfo &EBBI);
  void AlignFork(MBBInfo &EBBI);

  void ClassifyBranches();
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
  void PeformSensitivityAnalysis();

  void DetectOuterSensitiveBranches();
  void AnalyzeLoops();

  void CanonicalizeSensitiveLoop(MachineLoop *Loop);
  void AlignContainedRegions(MachineLoop *L);

  void SecureCalls();
  void AlignSensitiveBranches();

  void AlignSensitiveBranch(MBBInfo &BBI);
  std::vector<MachineBasicBlock *>
    AlignSensitiveLoop(MachineLoop *Loop, std::vector<MachineBasicBlock *> MBBs);
  std::vector<MachineBasicBlock *>
    AlignFingerprint(std::vector<MachineBasicBlock *> FP, std::vector<MachineBasicBlock *> MBBs);

  void WriteCFG(std::string label);
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

// TODO: Move this logic to MSP430InstrInfo
static bool isCGConstant(const int immediateValue) {
  switch (immediateValue) {
    case -1:
    case 0:
    case 1:
    case 2:
    case 4:
    case 8:
      return true;
    default:
      return false;
  }
}

// TODO: Move this logic (when to use one of the constant generator regs)
//    to MSP430InstrInfo
static const MCInstrDesc &
getCompareInstr(const TargetInstrInfo *TII, const int immediateValue) {
  return isCGConstant(immediateValue)
         ? TII->get(MSP430::CMP16rc)
         : TII->get(MSP430::CMP16ri);
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

// Creates a corresponding BBInfo entry in BBAnalysis
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
  // HasSecretDependentBranch is set in PeformSensitivityAnalysis, not in
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
  // BBI->IsLoopLatch = false;
  // BBI->TripCount = 0;
  BBI->Next = nullptr;
  BBI->TrueBB = nullptr;
  BBI->FalseBB = nullptr;
  BBI->FallThroughBB = nullptr;
  BBI->TerminatorCount = 0;
  BBI->BrCond.clear();
  BBI->Defs.clear();
  BBI->Deps.clear();
#if 0
  std::memset(&BBI->BCInfo, 0, sizeof(BBI->BCInfo));
#endif

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
    LLVM_DEBUG(dbgs() << "New MBB: " << GetName(MBB) << " (" << debug << ")\n");
  }
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
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16rc), MSP430::CG).addImm(0);
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

  // MOV  2(PC), R3    ; 3 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16rm), MSP430::CG)
      .addReg(MSP430::PC)
      .addImm(2);
}

static void BuildNOP4(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // BIC  #0, 0(R4)    ; 4 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::BIC16mi), MSP430::R4)
      .addImm(0)
      .addImm(0);
}

static void BuildNOP5(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  @R4, 0(R4)   ; 5 cycles, 2 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16mn), MSP430::R4)
      .addImm(0)
      .addReg(MSP430::R4);
}

static void BuildNOP6(MachineBasicBlock &MBB, MachineBasicBlock::iterator I,
                      const TargetInstrInfo *TII) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  // MOV  0(R4), 0(R4) ; 6 cycles, 3 words
  BuildMI(MBB, I, DL, TII->get(MSP430::MOV16mm), MSP430::R4)
      .addImm(0)
      .addReg(MSP430::R4)
      .addImm(0);
}

// TODO: MSP430 specific
// According to the MSP430 manual, a branch instruction always takes two cycles
// two execute, independent on whether a branch is taken or not
static void BuildNOPBranch(MachineBasicBlock &MBB,
                           MachineBasicBlock::iterator I,
                           const TargetInstrInfo *TII) {
  BuildNOP2(MBB, I, TII);
}

// Builds the fingerprint of the region. The fingerprint is a slice of the
//  region, a list of basic blocks that represents a unique path of through the
//  aligned region. It kind of represents "all possible paths" of the aligned
//  loop.
//
// PRE: The region (from header to latch in the case of loop regions) must be
//       aligned for the fingerprint to be correct. This means alignment of
//         - terminating instructions
//         - non-terminating instructions
//         - two-way branches
//
// Any control-flow path from loop-header to loop-latch should do, because
//  the loop region is already aligned (precondition) which means that all
//  possible paths from header to latch are observably equivalent.
//  Therefore, do a DFS traversal through the sensitive region.
void MSP430NemesisDefenderPass::BuildFingerprint(
    MachineLoop *L, std::vector<MachineBasicBlock *> &Result) {

  auto Header = L->getHeader();
  assert(Header != nullptr && "Well-formed loop expected");
  auto Latch = L->getLoopLatch();
  assert(Latch != nullptr && "Well-formed loop expected");

  // Build the fingerprint by performing a dept-first traversal.
  //  - Because of the well-formedness criterion, the last block of a DFS (in
  //    any path) should be the loop latch.
  //  - Assert that the following while-loop terminates, which is the case when
  //    the latch block post-dominates the header.
  assert(MPDT->dominates(Latch, Header) && "Well-formed loop expected");
  std::set<MachineBasicBlock *> Visited;
  MachineBasicBlock *PrevBB = nullptr;
  MachineBasicBlock *CurBB = Header;

  // REMARK: This must also work for paths that contain "artifical" loops
  while (CurBB != Latch) {
    assert(Visited.find(CurBB) == Visited.end() && "Well-formed loop expected");
    Visited.insert(CurBB);

    auto L2 = MLI->getLoopFor(CurBB);
    assert(L2 != nullptr);

    if (L2 == L) {
      auto BBI = GetInfo(*CurBB);

      Result.push_back(CurBB);

      // It is a precondition of this function that all sensitive regions in the
      // given loop are aligned. This means that the number of statements
      // should be the same for any path that is taken in the loop region. Still,
      // caution has to be taken for two-way branches because the second JMP is
      // only executed in the false branch.
      PrevBB = CurBB;
      if (BBI->IsConditionalBranch) {
        assert(CurBB->succ_size() == 2 && "Well-formed MBB expected");

        // Follow the false path to avoid compensating for the
        //   1) the "JMP" instruction from the (JCC, JMP) pair _and_
        //   2) the JMP-compensated instruction in the true path
        assert(BBI->BB->isSuccessor(BBI->TrueBB));
        assert(BBI->BB->isSuccessor(BBI->FalseBB));

        CurBB = BBI->FalseBB;
      } else {
        assert(CurBB->succ_size() == 1 && "Well-formed MBB expected");

        CurBB = *CurBB->succ_begin();
      }
    } else {
      // Deal with this nested loop
      assert(L2->getLoopPreheader() == PrevBB && "Well-formed loop expected");
      BuildFingerprint(L2, Result);

      // Continue with the loop-exit block
      PrevBB = CurBB;
      CurBB = L2->getExitBlock();
      assert(CurBB != nullptr && "Well-formed loop expected");
    }
  }

  Result.push_back(Latch);
}

// Fingerprint as a vector of MBBs
std::vector<MachineBasicBlock *>
MSP430NemesisDefenderPass::GetFingerprint(MachineLoop *L) {
  std::vector<MachineBasicBlock *> Result;
  BuildFingerprint(L, Result);
  return Result;
}

bool MSP430NemesisDefenderPass::IsTwoWayBranch(MBBInfo *BBI) {
  bool result = false;

  if (BBI->HasSecretDependentBranch) {
    if (BBI->IsConditionalBranch && (BBI->FallThroughBB == nullptr)) {
      assert(BBI->TerminatorCount == 2);
      result =  true;
    }
  }

  return result;
}

void MSP430NemesisDefenderPass::AlignTwoWayBranch(MachineBasicBlock &MBB) {
  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  auto BBI = GetInfo(MBB);

  assert(IsTwoWayBranch(BBI));

  auto T = MBB.getFirstTerminator();
  assert(T++->isConditionalBranch());
  assert(T++->isUnconditionalBranch());
  assert(T == MBB.end());

  LLVM_DEBUG(dbgs() << GetName(&MBB) << ": Align two-way branch\n");

  if ( std::all_of(BBI->TrueBB->pred_begin(), BBI->TrueBB->pred_end(),
      [this](MachineBasicBlock *MBB) {return this->IsTwoWayBranch(GetInfo(*MBB)); })) {
    // Compensate for the unconditional jump when the conditional jump has
    // been taken (in the true path).
    BuildNOPBranch(*BBI->TrueBB, BBI->TrueBB->begin(), TII);
  }
  else {
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
  }
}

// Returns
//   1) when one of the direct successors of MBBs represents the header of a
//        loop,
//      - Successors.Loop points to the hedear of the detected loop
//      - Successors.Succs represents the union of all successors of all MBBs
//         modulo the detected Loop header
//     The CFG will not be mutated.
//
//   2) otherwise
//      - Successors.Loop will be nullptr
//      - Successors.Succs represents the union of the direct successors of
//         every MMB in MBBs
//      Possibly mutates the MF (and its corresonding CFG) in order for the
//      preconditions of AlignNonTerminatingInstructions() to be valid.
//
// PRE: All MBB in MBBs are part of a sensitive region
// POST: R.Succs does not contain any duplicate blocks
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
  LLVM_DEBUG(dbgs() << "> Compute successors of ");
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

          LLVM_DEBUG(dbgs() << "Loop found :"
                            << " MBB=" << GetName(MBB)
                            << " S=" << GetName(S)
                            << " header=" << GetName(L2->getHeader())
                            << " latch=" << GetName(L2->getLoopLatch())
                            << " exit=" << GetName(L2->getExitBlock())
                            << "\n");

          if (! MLI->isLoopHeader(S)) {
            MF->viewCFG();
          }
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

            // Duplicates are not allowed in the Succs
            if (Set.find(S) == Set.end()) {
              Set.insert(S);
              R.Succs.push_back(S);
            }
          }
        }
      }
    }
    else {

      MachineBasicBlock *EmptyMBB = nullptr;

      // No loops found
      std::map<MachineBasicBlock *, MachineBasicBlock *> Clones; // DenseMap?
      for (auto MBB : MBBs) {
        for (auto S : MBB->successors()) {
          if ( (R.Loop == nullptr) || (S != R.Loop->getHeader()) ) {
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

                R.Succs.push_back(EmptyMBB);
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
              // Re-analyze because the empty MBB might be reused here.
              ReAnalyzeControlFlow(*EmptyMBB);

              // Loop analysis has to be redone because EmptyMBB might be part
              // of a loop, and loop analysis should be correct for the loop
              // detector to work correctly.
              // TODO: Optimize (see remark at function definition)
              // TODO: Optimize (this should be done only when EmptyMBB is created)
              RedoAnalysisPasses();

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
                    // Update sensitivity analysis and containedness
                    //   - HasSecretDependentBranch is set during sensitivity analysis
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

                R.Succs.push_back(Clone);
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
              // Duplicates are not allowed in Succs
              if (Set.find(S) == Set.end()) {
                Set.insert(S);
                R.Succs.push_back(S);
              }
            }
          }
        }
      }
    }
  }

  // Check postcondition: There should be no duplicates in Succs
  //
  // Remark: It is not possible to
  // use a std::set instead of a std::vector, because this would mean
  // that the order of insertion is not maintained. The order might be relevant
  // when effectively aligning the different blocks, because the order determines
  // the order in which the individual MBBs take the role as the reference block.
  std::set<MachineBasicBlock *> S(R.Succs.begin(), R.Succs.end());
  assert(S.size() == R.Succs.size());

  LLVM_DEBUG(dbgs() << "> successors: ");
  LLVM_DEBUG(for (auto MBB: R.Succs) dbgs() << GetName(MBB) << ", ");
  LLVM_DEBUG(dbgs() << "\n");

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
void MSP430NemesisDefenderPass::CanonicalizeTerminatingInstructions(
    MachineBasicBlock *MBB) {
  auto T = MBB->getFirstTerminator();
  LLVM_DEBUG(dbgs() 
      << "Canonicalize terminating instructions: " << GetName(MBB) << "\n");
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
  return SensitivityInfo.find(MI) != SensitivityInfo.end();
}

bool MSP430NemesisDefenderPass::IsSecretDependent(MBBInfo *BBI) {
  return BBI->HasSecretDependentBranch;
}

// Marks the given machine instruction as sensitive
void MSP430NemesisDefenderPass::Taint(MachineInstr * MI) {
  SensitivityInfo.insert(MI);

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
      HasSecretDependentBranch = true;
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

// Safe sensitivity analysis (uses use-def chain, the result of the
//  reaching definitions analysis) to statically track confidential
//  information. At first, only analyze registers, and conservatively
//  consider the rest as secret. To be extended
//  to stack slots and global variables.
//
// During sensitivity analysis, it is also determined whether the CFG needs to be
// canonicalized, i.e. transformed to a CFG with a single exit point (via calls
// to IsPartOfSensitiveRegion()). This analysis could not be done earlier,
// because there was no sensitivity info yet.
//
// !TODO: Desperately needs optimization
//         - Implement this as a worklist algo (needs a def-use chain)
//         - Store the sensitivity info in MBBInfo instead of a MF-level set?
void MSP430NemesisDefenderPass::PeformSensitivityAnalysis() {
  size_t N = 0;
  while (SensitivityInfo.size() > N) {
    N = SensitivityInfo.size();
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
        if (SensitivityInfo.find(&MI) == SensitivityInfo.end()) {

          if (MI.isInlineAsm()) {
            llvm_unreachable("Inline assembly is not supported");
          }

          if (MI.isCall()) {
            // TODO: the call should only be marked sensitive if one of the
            //       actual parameters is marked sensitive
            Taint(&MI);
            //continue;
          }

          // Mark every conditional branch that is part of a sensitive region
          // senstive in turn. (except for loop latches, see Taint())
          if (MI.isConditionalBranch()) {
            if (IsPartOfSensitiveRegion(&MI)) {
              Taint(&MI);
            }
          }

          for (auto &MO : MI.operands()) {
            if (SensitivityInfo.find(&MI) != SensitivityInfo.end()) {
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

              case MachineOperand::MO_GlobalAddress    :
              case MachineOperand::MO_MCSymbol         :
                // Be conservative and mark as sensitive
                Taint(&MI);
                break;

                // TODO: Gradually support more operand types
              case MachineOperand::MO_ExternalSymbol   :
              case MachineOperand::MO_ConstantPoolIndex:
              case MachineOperand::MO_FrameIndex       :
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
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
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

#if 0
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

// The branch classifier considers only 'sensitive' basic blocks as starting
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
#endif

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

  if (MI.isAnnotationLabel())
    return;

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

// Compensates the call with a call to a dummy and secure transformation of 
//  the callee
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
          N->append(std::string(MO.getGlobal()->getName()));
          break;
        default:
          llvm_unreachable("Usupported machine operand");
      }

      // TODO: Avoid string manipulation
      if (N->find(PREFIX_NEMDEF_DUMMY) > 0) {    // Read as: "if not startswith"
        if (N->find(PREFIX_NEMDEF_SECURE) == 0) {// Read as: "if startswith"
          N->erase(0, strlen(PREFIX_NEMDEF_SECURE));
        }
        N->insert(0, PREFIX_NEMDEF_DUMMY);
      }

      LLVM_DEBUG(dbgs() 
          << "  " << GetName(&MBB) << ": insert call (" << N->c_str() << ")\n");
      BuildMI(MBB, I, DL, TII->get(MSP430::CALLi)).addExternalSymbol(N->c_str());
      break;

#if 0
    // Sancus out calls
    case MSP430::BRCALLr:
      break;
#endif

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
// TODO: Why not use MBB->getFirstTerminator()
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

// Canonicalizes the sensitive loop
//
// It is important that this is done exactly once for every sensitive loop.
//   Canonicalization happens during a call to AlignContainedRegions which gets
//   called exactly once for every sensitive loop.
//
// ----------------------------------------------------------------------------
// Important principle to make sure the rest of the implementation does not
// get overly complicated:
//   => Once a region is aligned, it may not be changed anymore
// ----------------------------------------------------------------------------
//
// This method is called exactly once for each sensitive loop
//
// Adds a
//   - dummy preheader
//   - dummy exit
//   - dummy latch
void MSP430NemesisDefenderPass::CanonicalizeSensitiveLoop(MachineLoop *Loop) {
  auto Preheader = Loop->getLoopPreheader();
  auto Header = Loop->getHeader();
  auto Exit = Loop->getExitBlock();
  auto Latch = Loop->getLoopLatch();

  // Verify relevant parts of the well-formedness criterion
  assert(Preheader != nullptr);
  assert(Header != nullptr);
  assert(Latch != nullptr);
  assert(Exit != nullptr);

  DebugLoc DL; // FIXME: Where to get DebugLoc from?

  LLVM_DEBUG(dbgs() << "Canonicalize sensitive loop (H=" << GetName (Header) << ")\n");

  // 1) Create a new canonical loop preheader
  assert(Preheader->succ_size() == 1);
  assert(Preheader->isSuccessor(Header));
  auto NewPreheader = CreateMachineBasicBlock("loop-pheader", true);
  auto BBIPH = GetInfo(*NewPreheader);
  BBIPH->IsPartOfSensitiveRegion = true;
  BBIPH->IsCanonicalLoopBlock = true;
  // Compensate for (see AlignFingerprint)
  //   - push of induction register (MSP430::PUSH16r)
  //   - initialization of induction register to zero (MSP430::MOV16rc)
  BuildNOP3(*NewPreheader, NewPreheader->end(), TII);
  BuildNOP1(*NewPreheader, NewPreheader->end(), TII);
  NewPreheader->addSuccessor(Header);
  TII->insertBranch(*NewPreheader, Header, nullptr, {}, DL);
  ReplaceSuccessor(Preheader, Header, NewPreheader);

  // 2) Canonicalize the header block
  assert(Header->pred_size() == 2); // Preheader + latch
  auto BBIH = GetInfo(*Header);
  assert(BBIH->IsPartOfSensitiveRegion && "Sensitive loop expected");

  // 3) Canonicalize the latch block
  // Compensate for, just before the first terminator, (see AlignFingerprint)
  //   - the increment of induction register (MSP430::ADD16rc)
  //   - the comparison of the trip count with induction register
  //       (MSP430::CMP16ri or MSP430::CMP16rc)
  auto LT = Latch->getFirstTerminator();
  assert(LT != nullptr); // Guaranteed by well-formedness criterion, verified
                        //  by ComputeSuccessors. Every latch block should
                        //  have two successors, the loop header and the loop
                        //  exit block.
  BuildNOP1(*Latch, LT, TII);
  if (isCGConstant(BBIH->TripCount)) {
    BuildNOP1(*Latch, LT, TII);
  } else {
    BuildNOP2(*Latch, LT, TII);
  }
  // Make sure that there are exacaly two terminating instructions
  //   - one conditional jump to header
  //   - one unconditional jump to exit
  assert(Latch->succ_size() == 2);
  assert(Latch->isSuccessor(Header));
  assert(Latch->isSuccessor(Exit));

  // 4) Create a new canonical loop exit block
  auto NewExit = CreateMachineBasicBlock("loop-exit", true);
  auto BBIE = GetInfo(*NewExit);
  BBIE->IsPartOfSensitiveRegion = true;
  BBIE->IsCanonicalLoopBlock = true;
  // Compensate for pop of induction register (see AlignFingerprint)
  //       (MSP430::POP16r, emulated by MSP430::MOV16rp)
  BuildNOP2(*NewExit, NewExit->end(), TII);
  NewExit->addSuccessor(Exit);
  TII->insertBranch(*NewExit, Exit, nullptr, {}, DL);
  ReplaceSuccessor(Latch, Exit, NewExit);

  // (Re)do the necessary analyses
  AnalyzeControlFlow(*NewExit);
  AnalyzeControlFlow(*NewPreheader);
  RedoAnalysisPasses(); // TODO: Optimize, by manually updating the MLI
                        //         according to this canonicalization
                        // (=> update loop preheader and exit blocks)

  // Call CanonicalizeTerminatingInstructions here on the header, because the 
  //   sensitive loop region should be completely aligned when the fingerprint 
  //   is to be computed. AlignFingerprint depends on the principle:
  //             "aligned regions cannot change anymore"
  // It is important to canonicalize the terminating instructions after
  //  connecting the new preheader to the header (and creating an explicit
  //  unconditional jump)
  CanonicalizeTerminatingInstructions(Header);
}

static MachineLoop *
getLoopForHeader(MachineLoopInfo *MLI, MachineBasicBlock *Header) {
  auto L = MLI->getLoopFor(Header);
  assert(L != nullptr);
  assert(L->getHeader() != nullptr);
  assert(L->getHeader() == Header);
  return L;
}

// Remark: Recomputes analysis passes
void MSP430NemesisDefenderPass::AlignContainedRegions(MachineLoop *Loop)
{
  auto Header = Loop->getHeader();
  assert(Header != nullptr);

  // First canonicalize this sensitive loop
  auto BBIH = GetInfo(*Header);
  assert(BBIH->IsPartOfSensitiveRegion);
  CanonicalizeSensitiveLoop(Loop);

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
      Loop = getLoopForHeader(MLI, Header);
    }
  }
}

// Aligns all MBBs with the given fingerprint
//
//   Loopification code that is generated by this method is already compensated
//   for in the original loop by the "sensitive loop canonicalization" phase
//     (see CanonicalizeSensitiveLoop)
//
// Returns the list of successors of all sensitive regions, including the newly
//  ceated ones (the exit blocks in the case of loop regions). This is required
//  for the next call to ComputeSuccessors to compute the successors based on
//  the correct set.
//
// Remark: Recomputes analysis passes
//
// TODO: Generalize to support arbitary regions (e.g. can be used as primitive
//     for ad-hoc, pattern-based optimizations (see notes))
//
// TODO: Optimize generated code for size, by
//   1) putting the generated loop in a separate block and
//   2) generating calls to this block
std::vector<MachineBasicBlock *>
MSP430NemesisDefenderPass::AlignFingerprint(
        std::vector<MachineBasicBlock *> FP, std::vector<MachineBasicBlock *> MBBs) {

  std::vector<MachineBasicBlock *> Result;

  assert(FP.size() > 0);
  assert(MBBs.size() > 0);

  // - Pick an arbitrary register to act as the "induction register"
  //     TODO: Optimize: use one that is not live
  unsigned IReg = MSP430::R10;

  LLVM_DEBUG(dbgs() << ">> Align fingerprint: FP= ");
  LLVM_DEBUG(for (auto FPMBB : FP) dbgs() << GetName(FPMBB) << ",");
  LLVM_DEBUG(dbgs() << " MBBs=");
  LLVM_DEBUG(for (auto MBB : MBBs) dbgs() << GetName(MBB) << ",");
  LLVM_DEBUG(dbgs() << "\n");

  // When the last block of the fingerprint is a loop latch, push
  //  loop-exit block to the result
  auto BBI = GetInfo(*FP.back());
  if (BBI->IsLoopLatch) {
    auto Loop = MLI->getLoopFor(FP.back());
    assert(Loop != nullptr);
    assert(Loop->getLoopLatch() == FP.back());
    auto Exit = Loop->getExitBlock();
    assert(Exit != nullptr && "Well-formed loop expected");
    assert(GetInfo(*Exit)->IsCanonicalLoopBlock);
    Result.push_back(Exit);
  } else {
    Result.push_back(FP.back());
    llvm_unreachable("Non loop fingerprints not supported yet");
    // TODO: Requires changes to the computation of the Result vector
  }

  // Align each of the MBBs with the fingperprint
  for (auto MBB : MBBs) {

    DebugLoc DL; // FIXME: Where to get DebugLoc from?

    MachineBasicBlock *PrevMBB = nullptr;
    std::vector<MachineBasicBlock *> Headers;

    // Iterate over the fingerprint blocks
    for (auto FPMBB : FP) {

      auto FPBBI = GetInfo(*FPMBB);
      assert(FPBBI->IsPartOfSensitiveRegion);

      // Ignore canonical loop blocks of nested loops to avoid creating a BB
      // twice for them, since the pre-header and exit blocks are always
      //  (as in hardcoded) created by this method.
      //  (No need to do this for the outer most loop because the canonical
      //  loop blocks of the outer most loop are not part of the fingerprint).
      if (! FPBBI->IsCanonicalLoopBlock) {

        // Create a dummy MBB to align with this fingerprint block
        //  and insert it into the CFG
        auto CurMBB = CreateMachineBasicBlock("align-fp", true);
        auto CurBBI = GetInfo(*CurMBB);
        CurBBI->Orig = CloneMBB(CurMBB, false);
        CurBBI->IsPartOfSensitiveRegion = true;
        if (PrevMBB == nullptr) {
          assert(FPBBI->IsLoopHeader);
          auto Loop = getLoopForHeader(MLI, FPMBB);
          assert(Loop != nullptr);
          assert(MBB->pred_size() >= 1);
          std::vector<MachineBasicBlock *> L;
          for (auto Pred : MBB->predecessors()) {
            if (GetInfo(*Pred)->IsAligned) {
            // !!!!!!!TODO: Make sure this is well-understood
            //       (wrt nemdef-region-loop-loop-tail-O3.mir)
            //if (! MDT->dominates(Loop->getHeader(), Pred)) {
              L.push_back(Pred);
            }
          }
          for (auto Pred : L) {
            // Update CFG must be done outside of previous for loop,
            //  as it invalidates the Pred iterator
            ReplaceSuccessor(Pred, MBB, CurMBB);
          }
        }
        else {
          ReplaceSuccessor(PrevMBB, MBB, CurMBB);
        }
        CurMBB->addSuccessor(MBB);
        TII->insertBranch(*CurMBB, MBB, nullptr, {}, DL);
        AnalyzeControlFlow(*CurMBB);

        if (FPBBI->IsLoopHeader) {

          LLVM_DEBUG(dbgs()
              << ">> LOOPIFY FOR " << GetName(FPBBI->BB)
              << " @ " << GetName(CurMBB) << "\n");

          assert(FPBBI->TripCount > 0);

          // Make CurMBB the loop preheader
          //  (This block is already anticipated for in the real loop by
          //    CanonicalizeSensitiveLoop)
          //
          // Add instructions to the loop preheader that
          //    o push the current value of the induction register on the stack
          //    o initialize the induction register
          auto Preheader = CurMBB;
          CurBBI->IsCanonicalLoopBlock = true;
          auto T = Preheader->getFirstTerminator();
          assert(T != nullptr);
          BuildMI(*Preheader, T, DL, TII->get(MSP430::PUSH16r), IReg);
          BuildMI(*Preheader, T, DL, TII->get(MSP430::MOV16rc), IReg).addImm(0);

          // Create a new CurMBB and put it between the preheader and MBB blocks
          CurMBB = CreateMachineBasicBlock("align-fp-preheader", true);
          CurBBI = GetInfo(*CurMBB);
          CurBBI->Orig = CloneMBB(CurMBB, false);
          CurBBI->IsPartOfSensitiveRegion = true;
          assert(Preheader->succ_size() == 1);
          ReplaceSuccessor(Preheader, MBB, CurMBB);
          CurMBB->addSuccessor(MBB);
          TII->insertBranch(*CurMBB, MBB, nullptr, {}, DL);
          AnalyzeControlFlow(*CurMBB);

          // CurMBB will act as the loop header
          CurBBI->IsLoopHeader = true;
          CurBBI->TripCount = FPBBI->TripCount;

          Headers.push_back(CurMBB);
        }

        // Align non-terminating instructions
        // TODO: assert(noNonTerminatingInstructions(CurMBB);
        //    => otherwise, contents of FPMBB might change because of this
        //             (violates principle that aligned regions cannot change
        //               anymore)
        FPBBI->IsAligned = false; // HACK (The fingerprint represents an
                                  //          aligned region, so safe to do) 
                                  // (Aligned regions should not change anymore)
        AlignNonTerminatingInstructions({FPMBB, CurMBB});
        FPBBI->IsAligned= true;

        if (! FPBBI->IsLoopLatch) {
          // Align/fix terminating instructions (see paper on how to fix this)
          // Every block in the *aligned* loop region 
          //    either ends with exactly two terminating instructions 
          //    or either contains compensating instructions for two terminating
          //    instructions (guaranteed by CanonicalizeTerminatingInstructions)
          // !!!TODO: Hacky, there should be a more elgant way of dealing with 
          //      the (compensated) terminating instructions in the fingerprint
          if (FPBBI->TerminatorCount != 1) {
            auto T = CurMBB->getFirstTerminator();
            if (FPBBI->TerminatorCount == 0) {
              T--;
              T->removeFromParent();
            }
            else {
              assert(FPBBI->TerminatorCount == 2);
              BuildNOPBranch(*CurMBB, T, TII);
            }
          }
        }
        else {
          // A Canonical latch always end in two terminators
          assert(! Headers.empty());
          auto Header = Headers.back();
          assert(Header != nullptr);
          Headers.pop_back();
          auto HeaderBBI = GetInfo(*Header);

          CurBBI->IsLoopLatch = true;

          // Create the loop-exit block
          auto Exit = CreateMachineBasicBlock("align-fp-exit", true);
          auto ExitBBI = GetInfo(*Exit);
          ExitBBI->Orig = CloneMBB(Exit, false);
          ExitBBI->IsPartOfSensitiveRegion = true;
          ExitBBI->IsCanonicalLoopBlock = true;
          ExitBBI->IsAligned = true;

          // Connect latch to exit and header blocks
          auto BrCond = MachineOperand::CreateImm(MSP430CC::CondCodes::COND_L);
          CurMBB->replaceSuccessor(MBB, Exit);
          CurMBB->addSuccessor(Header);
          RemoveTerminationCode(*CurMBB);
          TII->insertBranch(*CurMBB, Header, Exit, BrCond, DL);
          ReAnalyzeControlFlow(*CurMBB);

          // Connect exit to MBB
          Exit->addSuccessor(MBB);
          TII->insertBranch(*Exit, MBB, nullptr, {}, DL);
          AnalyzeControlFlow(*Exit);

          // Restore the value of the induction register in the exit block
          BuildMI(*Exit, Exit->begin(), DL, TII->get(MSP430::POP16r), IReg);

          // Replace the two instructions preceding the terminators
          auto T = CurMBB->getFirstTerminator();
          auto MI1 = --T;
          auto MI2 = --T;
          T = CurMBB->getFirstTerminator();
          MI1->removeFromParent();
          MI2->removeFromParent();
          BuildMI(*CurMBB, T, DL, TII->get(MSP430::ADD16rc), IReg)
            .addReg(IReg)
            .addImm(1);
          BuildMI(*CurMBB, T, DL, getCompareInstr(TII, HeaderBBI->TripCount), IReg)
            .addImm(HeaderBBI->TripCount);

           CurMBB = Exit;
        }

        PrevMBB = CurMBB;
      }
    }

    assert(Headers.empty());
    assert(PrevMBB != nullptr);

    Result.push_back(PrevMBB);
  }

  RedoAnalysisPasses(); // TODO: Optimize (see remark at function definition)

  LLVM_DEBUG(dbgs() << "> successors: ");
  LLVM_DEBUG(for (auto MBB: Result) dbgs() << GetName(MBB) << ", ");
  LLVM_DEBUG(dbgs() << "\n");

  return Result;
}

// AlignSensitiveLoop performs the following actions:
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
  Loop = getLoopForHeader(MLI, Header);
  assert(LoopLatch == Loop->getLoopLatch());

#if 0
  assert(Loop->getExitBlock() != nullptr);
  auto BBIE = GetInfo(*Loop->getExitBlock());
  //BBIE->IsAligned = true;
#endif

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
  //MPDT->runOnMachineFunction(*MF);
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
  while (!Succs.Succs.empty()) {
    // TODO: Make sure this loop terminates
    if (Succs.Loop == nullptr) {
      assert(Succs.Succs.size() > 1);
      AlignNonTerminatingInstructions(Succs.Succs);
      std::copy(Succs.Succs.begin(), Succs.Succs.end(), std::back_inserter(MBBs));
      Succs = ComputeSuccessors(Succs.Succs, ExitOfSR);
    }
    else {
      // A loop has been detected by ComputeSuccessors, deal with it first
      auto S = AlignSensitiveLoop(Succs.Loop, Succs.Succs);

#if 1
      auto E = Succs.Loop->getExitBlock();
      assert(E != nullptr);
      auto BBIE = GetInfo(*E);
      BBIE->IsAligned = true;
#endif

#if 0
      // CanonicalizeTerminatingInstructions is already called in 
      //   CanonicalizeSensitiveLoop for loop headers
      auto H = Succs.Loop->getHeader();
      assert(H != nullptr);
      MBBs.push_back(H);
#endif

      Succs = ComputeSuccessors(S, ExitOfSR);
    }
  }

  // 2) Canonicalize terminating instructions
  for (auto MBB : MBBs) {
    MBBInfo *BBI = GetInfo(*MBB);

    assert(BBI->IsAligned);

    // Aligning the termination instructions should be done after aligning
    // the non-termination instructions of all MBBs in the sensitive branch.
    // This is because the termination code can still change when aligning
    // one of the successor blocks (e.g. when an empty block is inserted).
    CanonicalizeTerminatingInstructions(BBI->BB);
  }

  // 3) Align two-way branches
  MBBs.push_back(BBI.BB); // Don't forget to include the entry block
  for (auto MBB : MBBs) {
    MBBInfo *BBI = GetInfo(*MBB);

    // Aligning two-way branches should be done after aligning the
    // non-terminating instructions because the instruction that gets inserted
    // in the true path, to compensate for the JMP in the false path,
    // does not have to be taken into account when aligning the MBBs at the
    // same level (See AlignNonTerminatingInstructions), because technically
    // this compensating
    // instruction belongs the previous MBB (or you could say that it is an
    // artifact of how two-way branches need to be represented in MIR).
    if (IsTwoWayBranch(BBI)) {
      AlignTwoWayBranch(*MBB);
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
        auto Latch = L->getLoopLatch();
        assert(Latch != nullptr);
        assert(L->getExitBlock() != nullptr);
        assert(L->getLoopLatch()->isSuccessor(L->getExitBlock()));
        assert(*L->getLoopPreheader()->succ_begin() == L->getHeader());

#if 0
        // !!TODO
        // Check some constraints of the well-formedness criterion
        // Latch should end with a conditional jump, followed by an
        //   unconditional jump
        assert(std::distance(Latch->terminators().begin(),
                             Latch->terminators().end()) == 2);
#endif

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

        GetInfo(*Latch)->IsLoopLatch = true;
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
          N->append(std::string(MO.getGlobal()->getName()));
          break;
        default:
          llvm_unreachable("Usupported machine operand");
      }

      // TODO: Avoid string manipulation
      if (N->find(PREFIX_NEMDEF_SECURE) > 0) {  // Read as: "if not startswith"
        if (N->find(PREFIX_NEMDEF_DUMMY) > 0) { // Read as: "if not startswith"
          N->insert(0, PREFIX_NEMDEF_SECURE);
          MO.ChangeToES(N->c_str());
        }
      }

      break;

#if 0
    // !!!!TODO: Sancus out calls
    case MSP430::BRCALLr:
      break;
#endif

    case MSP430::CALLm:
    case MSP430::CALLn:
    case MSP430::CALLp:
    case MSP430::CALLr:
    default:
      LLVM_DEBUG(dbgs() << "OPCODE=" << Call.getOpcode() << "\n");
      LLVM_DEBUG(dbgs() << Call);
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

void MSP430NemesisDefenderPass::WriteCFG(std::string label)
{
#if !defined(NDEBUG)
  if (SaveCFG) {
    std::string Filename = MF->writeCFG();
    assert(!Filename.empty());
    std::ifstream Src(Filename, std::ios::binary);
    std::ofstream Dst(
      (MF->getName() + Twine(".", label) + ".dot").str(), std::ios::binary);
    Dst << Src.rdbuf();
  }
#endif
}

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
        if (BBI.FalseBB) {
          O << GetName(BBI.BB) << " ->" << GetName(BBI.FalseBB) << ";\n";
        }
        if (BBI.TrueBB) {
          O << GetName(BBI.BB) << " ->" << GetName(BBI.TrueBB) << ";\n";
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
  //  represent the CC defs. Add them to the sensitivity set when their corresponding
  //  argument is marked "_secret". This allows for a uniform and therefore
  //  simpler sensitivity analysis implementation.
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
    auto MI = BuildMI(MBB, MBBI, DL, TII->get(MSP430::MOV16rc), Reg++).addImm(0);
    if (IsSecret(Arg)) {
      SensitivityInfo.insert(MI);
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

// Canonicalizes the CFG when necessary (determined during sensitivity analysis).
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

  HasSecretDependentBranch = false;
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

  WriteCFG("before"); 

  if (EmitCFG) {
#if 0
    MF.viewCFG(); // Dump unhardened CFG before any possible changes
#else
    MF.viewCFGOnly(); // Dump unhardened CFG before any possible changes
#endif
  }

  // Perform analysis
  PrepareAnalysis();
  AnalyzeControlFlow();
  VerifyControlFlowAnalysis();
  ComputeReachingDefs();

  PeformSensitivityAnalysis();
#if 0
  ClassifyBranches();
#endif
  FinishAnalysis();

  // Canonicalize CFG, if needed
  CanonicalizeCFG();

  if (EmitCFG) {
#if 0
    MF.viewCFG(); // Dump after canonicalization, before hardening
#else
    MF.viewCFGOnly(); // Dump after canonicalization, before hardening
#endif
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

  if (HasSecretDependentBranch)
    WriteCFG("after"); 

  return Changed;
}

void MSP430NemesisDefenderPass::releaseMemory() {
  BBAnalysis.clear(); // TODO: Does this also clear Defs and Deps?
  InstIds.clear();
  SensitivityInfo.clear();

  CanonicalExit = nullptr;
  EntryBBI = nullptr;
  HasSecretDependentBranch = false;
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
