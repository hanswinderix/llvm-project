#ifndef SLLVM_ANALYSIS_H
#define SLLVM_ANALYSIS_H

#include <set>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace sllvm {
  class SLLVMAnalysisResults {
    bool _isPM;
    std::set<const Function *> EEDefs; // Enclave entry points
    std::set<const Function *> EFuncs; // Enclave functions (private function)
    /* EXDefs is required by the SGX tranformation pass. 
     *
     * TODO: The SGX transformation pass is currently broken because of the 
     *        recent support for cross compilation unit protected modules 
     *        (XCU-PM), resulting in an incomplete gathering of information 
     *        about an enclave's interaction with the untrusted context, such 
     *        as information about the EXDefs.
     */
    std::set<const Function *> EXDefs; // The external functions that the
                                       //  enclave depends on
    
    // TODO: Rename to ECalls and OCalls ?
    std::set<const Instruction *> EECalls; // Enclave enter calls
    std::set<const Instruction *> EXCalls; // Enclave exit calls

    std::set<const GlobalVariable *> EData; // Enclave data (private data)

    std::string ModuleName;

    public:

    SLLVMAnalysisResults(const Module &M);

    bool isPM() const { return _isPM; }

    bool isEEntryDef(const Function *F) const { 
      return EEDefs.find(F) != EEDefs.end(); 
    }

    bool isEFunc(const Function *F) const { 
      return EFuncs.find(F) != EFuncs.end(); 
    }

    bool isEEntryCall(const Instruction *I) const {
      return EECalls.find(I) != EECalls.end(); 
    }

    bool isEExitCall(const Instruction *I) const { 
      return EXCalls.find(I) != EXCalls.end(); 
    }

    bool isEData(const GlobalVariable *GV) const { 
      return EData.find(GV) != EData.end(); 
    }

    const std::set<const Function *> &getEntryPoints() const {
      return EEDefs;
    }

    const std::set<const Function *> &getExternalFunctions() const {
      return EXDefs;
    }

    const std::string getModuleName() const {
      return ModuleName;
    }
  };

  class SLLVMAnalysis : public ModulePass {
    std::unique_ptr<SLLVMAnalysisResults> R;

    public:
    static char ID;

    SLLVMAnalysis() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;

    const SLLVMAnalysisResults &getResults() const { return *R; }

    // TODO: Is it necessary to clear the sets
    void releaseMemory() override { R.reset(); }
  };
}

#endif
