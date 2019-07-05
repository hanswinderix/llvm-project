#ifndef SLLVM_SANCUS_TRANSFORMATION_H
#define SLLVM_SANCUS_TRANSFORMATION_H

#include "llvm/IR/Module.h"

using namespace llvm;

namespace sllvm {
  class SancusTransformation : public ModulePass {
    public:
      static char ID;

      SancusTransformation() : ModulePass(ID) {}

      bool runOnModule(Module &M) override;

    private:

      void getAnalysisUsage(AnalysisUsage &A) const override;

      void createGlobals(Module &M);

      void createDispatch(Module &M);
      
      void setSections(Module &M);

      void createDispatchBody(Module &M, Function *D);

      void handleCalls(Module &M);

      void handleEnclave(Module &M);

      void handleStacklessEnclave(Module &M);

      void createSancusModuleStruct(Module &M);
  };
}

#endif
