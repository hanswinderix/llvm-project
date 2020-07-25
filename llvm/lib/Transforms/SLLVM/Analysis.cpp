#include "Analysis.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/SLLVM.h"
#include "llvm/Support/Debug.h"

#define DEBUG_TYPE "sllvm"

using namespace sllvm;

char SLLVMAnalysis::ID = 0;

static RegisterPass<SLLVMAnalysis> X("sllvm-analyze", "SLLVM analysis pass");

bool SLLVMAnalysis::runOnModule(Module &M) {
  R.reset(new SLLVMAnalysisResults(M));
  return false;
}

// TODO: Improve functional decomposition
SLLVMAnalysisResults::SLLVMAnalysisResults(const Module &M) : _isPM(false) {

  // 1. Derive module name from source filename
  ModuleName = M.getSourceFileName();

  auto idx = ModuleName.find_last_of("/");
  if (idx != std::string::npos) {
    // Strip path
    ModuleName = ModuleName.substr(idx+1);
  }

  idx = ModuleName.find_first_of(".");
  if (idx != std::string::npos) {
    // Strip file extensions
    ModuleName = ModuleName.substr(0, idx);
  }

  std::replace(ModuleName.begin(), ModuleName.end(), '-', '_');

  LLVM_DEBUG(dbgs() << ModuleName << "\n");

  for (const Function& F : M) {
    // 2. Detect enclave entry function definitions
    if ( (! F.isDeclaration()) && isEEntry(&F)) {
      assert(!F.hasLocalLinkage()); // TODO: Enforce this in CFE
      EEDefs.insert(&F);
      auto PD = getProtectionDomain(&F);
      if (PD.empty() || (PD.compare(ModuleName) == 0)) {
        _isPM = true;
      }
    }

    // 3. Detect private enclave function defintions
    if (! F.isDeclaration()) {
      if (F.hasLocalLinkage() || sllvm::isEFunc(&F)) {
        EFuncs.insert(&F);
      }
    }
  }

  // 4. Detect ECalls and OCalls
  for (const Function& F : M) {
    for (const BasicBlock &BB : F) {
      for (const Instruction &I : BB) {
        if (auto *CB = dyn_cast<CallBase>(&I)) {
          const Function *CF = CB->getCalledFunction();
          if (CF != nullptr) { // TODO: Forbid indirect calls in enclaves

            if (isEEntry(CF)) {
              if (! isProtected(&F)) {
                // En entry call from within a public function should *always*
                // be treated as an enclave entry call, even if the public
                // function is defined in the same LLVM Module
                EECalls.insert(&I);
              }
              if ( ! shareProtectionDomains(&F, CF) ) {
                EECalls.insert(&I);
                EXDefs.insert(CF); /* Required by SGX Transformation pass */
              }
            }

            if (isProtected(&F)) {
              if ( (! shareProtectionDomains(&F, CF))) {
                // TODO: Treat intrinsic calls as exit calls too ! (except 
                //         for the EENTER and EEXIT intrinsics of course)
                if (! CF->isIntrinsic()) {
                  EXCalls.insert(&I);
                  EXDefs.insert(CF); /* Required by SGX transformation pass */
                }
              }
            }
          }
        }
      }
    }
  }

  // 5. Detect enclave data
  for (auto GVI = M.global_begin(), E = M.global_end(); GVI != E; GVI++) {
    if (GVI->hasLocalLinkage() || sllvm::isEData(&*GVI)) {
      // TODO: Not sure if the following line is correct for excluding
      //       string literals from the enclave data. Probably it is excluding
      //       too much. Rewrite it so that only string literals are excluded.
      if (! (GVI->isConstant() && GVI->hasAtLeastLocalUnnamedAddr()) ) {
        EData.insert(&*GVI);
      }
    }
  }
}
