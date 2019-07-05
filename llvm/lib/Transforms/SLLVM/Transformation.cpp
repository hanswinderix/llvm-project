#include "Transformation.h"
#include "Analysis.h"
#include "llvm/SLLVM.h"

#define DEBUG_TYPE "sllvm"

using namespace sllvm;

// TODO: Improve functional decomposition and get rid of copy-paste code in
//         canonicalization step
bool SLLVMTransformation::runOnModule(Module &M) {
  bool result = false;

  auto A = getAnalysis<SLLVMAnalysis>().getResults();
  if (A.isPM()) {

    // Indicate that this is a protected module by setting the PM module flag
    M.addModuleFlag(Module::Override, sllvm::module_flag_pm, 
        llvm::MDString::get(M.getContext(), A.getModuleName()));

    // Convert all attributes to their canonical representation
    for (Function& F : M) {

      // Convert "eentry" attributes to their canonical representation
      if (A.isEEntryDef(&F)) {
        assert(F.hasFnAttribute(sllvm::attribute_eentry));
        auto Attr = F.getFnAttribute(sllvm::attribute_eentry);
        if (Attr.getValueAsString().empty()) {
          F.addFnAttr(sllvm::attribute_eentry, A.getModuleName());
        }
      }

      // Convert "efunc" attributes to their canonical representation
      if (A.isEFunc(&F)) {
        if (! F.hasFnAttribute(sllvm::attribute_efunc)) {
          F.addFnAttr(sllvm::attribute_efunc, A.getModuleName());
        }
        else {
          auto Attr = F.getFnAttribute(sllvm::attribute_efunc);
          if (Attr.getValueAsString().empty()) {
            F.addFnAttr(sllvm::attribute_efunc, A.getModuleName());
          }
        }
      }
    }

    // Convert "edata" attributes to their canonical representation
    for (auto GVI = M.global_begin(), E = M.global_end(); GVI != E; GVI++) {
      if (A.isEData(&*GVI)) {
        if (! GVI->hasAttribute(sllvm::attribute_edata)) {
          GVI->addAttribute(sllvm::attribute_edata, A.getModuleName());
        }
        else {
          auto Attr = GVI->getAttribute(sllvm::attribute_edata);
          if (Attr.getValueAsString().empty()) {
            GVI->setAttributes(GVI->getAttributes().removeAttribute(
                GVI->getContext(), sllvm::attribute_edata));
            GVI->addAttribute(sllvm::attribute_edata, A.getModuleName());
          }
        }
      }
    }

    result = true;
  }

  return result;
}

char SLLVMTransformation::ID = 0;

static RegisterPass<SLLVMTransformation> X(
    "sllvm-transform", "SLLVM transformation pass");

void SLLVMTransformation::getAnalysisUsage(AnalysisUsage &A) const {
  A.addRequired<SLLVMAnalysis>();
}
