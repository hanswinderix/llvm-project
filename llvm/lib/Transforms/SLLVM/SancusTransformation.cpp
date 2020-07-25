#include "SancusTransformation.h"
#include "Analysis.h"
#include "../lib/Target/MSP430/MSP430Sancus.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/CommandLine.h"

#define DEBUG_TYPE "sllvm"

using namespace sllvm::sancus;

static cl::opt<bool> FixDataSection(
    "fix-data-section",
    cl::desc("Fix data section"),
    cl::init(false),
    cl::Hidden);

static cl::opt<unsigned> KeySize(
    "key-size",
    cl::desc("Key size in number of bits"),
    cl::init(64),
    cl::Hidden);

static cl::opt<unsigned> StackSize(
    "stack-size",
    cl::desc("Stack size in number of bytes"),
    cl::init(128),
    cl::Hidden);

static cl::opt<unsigned> VendorId(
    "vendor-id",
    cl::desc("The protected module's vendor id"),
    cl::init(0x1234),
    cl::Hidden);

static uint32_t getKeyBitSize() { return KeySize; }
static uint32_t getKeyByteSize() { return (getKeyBitSize() + 7) / 8; }

// Returns tuple (EntryFunc, EntryFuncID)
static std::pair<Value *, Value *>
getOrInsertEEntryFunction(Module &M, const Function *F) {
  assert(F != nullptr);
  assert(isEEntry(F));

  Type * Int16Ty = Type::getInt16Ty(M.getContext());
  FunctionType *FTy = cast<FunctionType>(F->getValueType());

  SmallVector<Type *, 6> P {Int16Ty};
  P.insert(std::end(P), FTy->params().begin(), FTy->params().end());
  FunctionType *Ty = FunctionType::get(FTy->getReturnType(), P, false);

  auto N = getDispatcherAliasName(F);
  Function *S = dyn_cast<Function>(M.getOrInsertFunction(N, Ty).getCallee());
  Value *EF;

  if (S == nullptr) {
    // This must be for an entry call from within a public enclave function.
    // (Support for public enclave functions was needed to be able to compile 
    //  the official Sancus examples.) If this statement is true, then N 
    //  should be an alias for the dispatcher...
    auto A = M.getNamedAlias(N);
    assert (A != nullptr);
    PointerType *T = PointerType::get(Ty, 0);
    S = M.getFunction(getDispatcherName(F));
    assert(S == A->getAliasee());
    assert(S->getCallingConv() == CallingConv::SANCUS_ENTRY);
    assert(shareProtectionDomains(&M, F));
    EF = ConstantExpr::getBitCast(S, T);
  }
  else {
    S->setCallingConv(CallingConv::SANCUS_ENTRY);
    S->addFnAttr(sllvm::attribute_eentry);
    EF = S;
  }

  GlobalVariable *ID = dyn_cast<GlobalVariable>(
      M.getOrInsertGlobal(getEntryPointIdentifierName(F), Int16Ty));
  ID->setConstant(true);

  return std::make_pair(EF, ID);
}

static GlobalVariable * newVariable(Module &M, StringRef N, Type *T) {
  GlobalVariable * R = M.getNamedGlobal(N);
  if (R == nullptr) {
    assert(M.getNamedValue(N) == nullptr);
    auto L = GlobalVariable::WeakAnyLinkage;
    auto I = Constant::getNullValue(T);
    R = new GlobalVariable(M, T, false, L, I, N);
    assert(M.getNamedValue(N) != nullptr);
  }
  return R;
}

template<typename T> 
static GlobalVariable * 
newSecretVariable(Module &M, StringRef N, Type *t, T D) {
  auto R = newVariable(M, N, t);
  R->setSection(getDataSectionName(D));
  return R;
}

static GlobalVariable * newSecretVariable(Module &M, StringRef N, Type *T) {
  return newSecretVariable(M, N, T, &M);
}

static GlobalVariable * 
replaceOrInsertVariable(Module &M, Type *T, StringRef N) {
  auto L = GlobalValue::ExternalLinkage;
  auto I = Constant::getNullValue(T);
  GlobalVariable *GV = new GlobalVariable(M, T, false, L, I);
  auto NG = M.getNamedGlobal(N);
  if (NG != nullptr) {
    // TODO: Handle existing definitions more gracefully
    //        (also when they come from extern declaration in C)
    //assert(GV->getType() == ArTy && "Unexpected type");
    NG->replaceAllUsesWith(GV);
    NG->eraseFromParent();
  }
  GV->setName(N);

  return GV;
}

static GlobalVariable * 
newArrayVariable(Module &M, StringRef Name, uint64_t NumElements) {
  Type *Int8Ty = Type::getInt8Ty(M.getContext());
  Type *ArTy = ArrayType::get(Int8Ty, NumElements);

  auto result = replaceOrInsertVariable(M, ArTy, Name);
  result->setLinkage(GlobalValue::InternalLinkage);

  return result;
}

static FunctionType * getDispatchType(Module &M) {
  Type * VoidTy = Type::getVoidTy(M.getContext());
  Type * Int16Ty = Type::getInt16Ty(M.getContext());
  Type *P[] = {Int16Ty, Int16Ty, Int16Ty, Int16Ty, Int16Ty};
  return FunctionType::get(VoidTy, P, false);
}

// TODO: Refactor. Now that cross-compilation unit PMs are supported, 
//        createGlobals is not applicable to PMs anymore. See for example
//        handleCalls() that also creates globals. This is also required
//        to support multi-protection domain compilation units.
void SancusTransformation::createGlobals(Module &M) {
  IRBuilder<> IRB(M.getContext());

  // Secret variable representing the protected module's local stack
  Type *Int16Ty = IRB.getInt16Ty();
  Type *ArTy = ArrayType::get(Int16Ty, StackSize);
  auto S = newSecretVariable(M, getLocalStackName(&M), ArTy);

  // Secret variable for storing local stack pointer
  Constant *IdxList[] = {
    ConstantInt::get(Int16Ty, 0),
    ConstantInt::get(Int16Ty, StackSize-1)
  };
  auto C = ConstantExpr::getGetElementPtr(nullptr, S, IdxList);
  auto lr1 = newSecretVariable(M, getLocalR1Name(&M), C->getType());
  lr1->setInitializer(C);

  // Secret variable for storing address of local stack pointer variable
  //  The linker will put this symbol at the end of the PM's data section 
  //  as expected by the secure IRQ hardware.
  auto lr1_addr = newSecretVariable(M, getLocalR1AddrName(&M),
      PointerType::get(C->getType(), 0));
  lr1_addr->setInitializer(lr1);
  lr1_addr->setSection(getLocalR1AddrSectionName(&M));

  // Secret variables for storing register contents
  newSecretVariable(M, getLocalR4Name(&M), Int16Ty);
  newSecretVariable(M, getLocalR5Name(&M), Int16Ty);
  newSecretVariable(M, getLocalR8Name(&M), Int16Ty);
  newSecretVariable(M, getLocalR9Name(&M), Int16Ty);
  newSecretVariable(M, getLocalR10Name(&M), Int16Ty);
  newSecretVariable(M, getLocalR11Name(&M), Int16Ty);

  for (auto GVI = M.global_begin(), E = M.global_end(); GVI != E; GVI++) {
    if (getAnalysis<SLLVMAnalysis>().getResults().isEData(&*GVI)) {
      if (GVI->hasCommonLinkage()) {
        GVI->setLinkage(GlobalValue::WeakAnyLinkage);
      }
    }
  }

  // Public variable for storing the tag used for confidential loading
  auto T = newArrayVariable(M, getTagName(&M), getKeyByteSize());
  T->setSection(getWrapSectionName(&M));

  // Public variable for storing the nonce used for confidential loading
  auto N = replaceOrInsertVariable(M, Int16Ty, getNonceName(&M));
  N->setSection(getWrapSectionName(&M));
}

void SancusTransformation::createDispatchBody(Module &M, Function *D) {
  LLVMContext &C = M.getContext();
  IRBuilder<> IRB(C);
  IntegerType * Int16Ty = IRB.getInt16Ty();

  BasicBlock *EntryBB = BasicBlock::Create(C, "entry", D);
  BasicBlock *DefBB = BasicBlock::Create(C, "default", D);
  BasicBlock *EpiBB = BasicBlock::Create(C, "epilog", D);
  BasicBlock *ReturnBB = BasicBlock::Create(C, "ereturn", D);

  IRB.SetInsertPoint(EntryBB);
  if (!hasFixedDataSection(&M)) {
    IRB.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::sllvm_eenter));
  }
  SwitchInst *SI = IRB.CreateSwitch(D->arg_begin(), DefBB, 5);

  IRB.SetInsertPoint(DefBB);
  IRB.CreateBr(EpiBB); // TODO: Exit instead of EpiBB

  IRB.SetInsertPoint(EpiBB);
  if (!hasFixedDataSection(&M)) {
    IRB.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::sllvm_eexit));
  }
  IRB.CreateRetVoid(); // TODO: Should be a RETE intrinsic for stackless PMs

  IRB.SetInsertPoint(ReturnBB);
  if (!hasFixedDataSection(&M)) {
    IRB.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::sllvm_ereturn));
  }
  IRB.CreateRetVoid(); // TODO: Remove

  SI->addCase(ConstantInt::get(Int16Ty, R6_PRet), ReturnBB);
  SI->addCase(ConstantInt::get(Int16Ty, R6_URet), ReturnBB);

  int id = 1;
  for (Function& F : M) {
    if (sllvm::isEEntry(&F)) {
      if (&F != D) {
        assert(! F.hasLocalLinkage());
        if (sllvm::shareProtectionDomains(&M, &F)) { 
          assert(F.arg_size() <= 4 && "Argument spilling not supported");

          BasicBlock * BB = BasicBlock::Create(C, F.getName(), D);
          SI->addCase(ConstantInt::get(Int16Ty, id), BB);
          IRB.SetInsertPoint(BB);

          // TODO: Optimize. The type conversions below should not be necessary 
          //       as the values are already in the correct argument registers 
          //       (R12-R15)
          SmallVector<Value *, 4> args;
          auto DAI = D->arg_begin();
          for (Argument &A : F.args()) {
            DAI++;
            assert(DAI != D->arg_end());
            assert(A.getType()->isSingleValueType() && "No register type");

            if (A.getType() == DAI->getType()) {
              args.push_back(DAI);
            }
            else if (A.getType()->isPointerTy()) {
              args.push_back(IRB.CreateIntToPtr(DAI, A.getType()));
            }
            else if (A.getType()->isIntegerTy()) {
              args.push_back(IRB.CreateIntCast(DAI, A.getType(), false));
            }
            else {
              assert(false && "TODO: Support more types?");
            }
          }

          auto I = IRB.CreateCall(&F, args);
          if (! hasStack(&M)) {
            I->setCallingConv(CallingConv::SANCUS_DISPATCH);
          }
          IRB.CreateBr(EpiBB);

          // Create constant identifier for this entry function
          new GlobalVariable(M, Int16Ty, true, GlobalValue::ExternalLinkage,
              ConstantInt::get(Int16Ty, id), getEntryPointIdentifierName(&F));

          // Create a dispatcher alias for this entry function
          GlobalAlias::create(GlobalValue::ExternalLinkage,
              getDispatcherAliasName(&F), D);

          id++;
        }
      }
    }
  }
}

void SancusTransformation::createSancusModuleStruct(Module &M) {
  LLVMContext &Ctx = M.getContext();
  auto TyName = "struct.SancusModule";
  auto SancusModuleTy = M.getTypeByName(TyName);

  if (SancusModuleTy == nullptr) {
    SancusModuleTy = StructType::create(Ctx, 
    { 
      Type::getInt16Ty(Ctx), 
      Type::getInt16Ty(Ctx), 
      Type::getInt8PtrTy(Ctx),
      Type::getInt8PtrTy(Ctx),
      Type::getInt8PtrTy(Ctx),
      Type::getInt8PtrTy(Ctx),
      Type::getInt8PtrTy(Ctx) 
    }, 
    TyName);
  }
  else {
    // The Sancus struct is already defined, e.g. by including "sm_support.h".
    assert(SancusModuleTy->isStructTy());
    // TODO: assert type ==  {int16, int16, int8*, int8*, int8*, int8*, int8*}
  }

  auto V = ConstantDataArray::getString(M.getContext(), getPMName(&M));
  auto GV = new GlobalVariable(
      M, V->getType(), true, GlobalValue::PrivateLinkage, V);
  GV->setAlignment(MaybeAlign(1));

  Constant *IdxList[] = {
    Constant::getNullValue(Type::getInt8Ty(Ctx)),
    Constant::getNullValue(Type::getInt8Ty(Ctx))
  };

  Type *Int8Ty = Type::getInt8Ty(Ctx);

  Constant *Vals[] = {
    ConstantInt::get(Type::getInt16Ty(Ctx), 0),
    ConstantInt::get(Type::getInt16Ty(Ctx), VendorId),
    ConstantExpr::getInBoundsGetElementPtr(V->getType(), GV, IdxList),

    M.getOrInsertGlobal(getStartOfTextSectionName(&M), Int8Ty),
    M.getOrInsertGlobal(getEndOfTextSectionName(&M), Int8Ty),
    M.getOrInsertGlobal(getStartOfDataSectionName(&M), Int8Ty),
    M.getOrInsertGlobal(getEndOfDataSectionName(&M), Int8Ty),
  };

  auto Init = ConstantStruct::get(SancusModuleTy, Vals);
  GV = dyn_cast<GlobalVariable>(
      M.getOrInsertGlobal(getPMName(&M), SancusModuleTy));
  GV->setConstant(false);
  GV->setLinkage(GlobalValue::ExternalLinkage);
  GV->setInitializer(Init);
  GV->setDSOLocal(true);
  GV->setAlignment(MaybeAlign(2));
}

void SancusTransformation::createDispatch(Module &M) {
  Function *F = Function::Create(getDispatchType(M),
      GlobalValue::ExternalLinkage, getDispatcherName(&M), &M);

  assert(getAnalysis<SLLVMAnalysis>().getResults().isPM());

  // The dispatcher represents the PM's physical entry point. The linker will 
  //  put the dispatcher in the beginning of the PM's text section.
  F->setCallingConv(CallingConv::SANCUS_ENTRY);
  F->addFnAttr(sllvm::attribute_eentry, getPMName(&M));
  F->setSection(getDispatchSectionName(&M));

  createDispatchBody(M, F);
}

void SancusTransformation::handleCalls(Module &M) {
  IRBuilder<> IRB(M.getContext());
  Type * Int16Ty = Type::getInt16Ty(M.getContext());

  std::vector<Instruction *> ECalls;

  auto A = getAnalysis<SLLVMAnalysis>().getResults();
  for (Function& F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);

        if (A.isEExitCall(&I)) {
          // Make sure the PM's dispatcher and the local stack pointer are 
          // known in the current Module. If not, the MSP430 backend is not 
          // able to generate code that a.o. saves the local stack pointer or 
          // sets the return address in R7. See MSP430ISelLowering.
          M.getOrInsertFunction(getDispatcherName(&F), getDispatchType(M));
          newVariable(M, getLocalR1Name(&F), Int16Ty);
        }

        if (A.isEEntryCall(&I)) {
          IRB.SetInsertPoint(&I);
          ECalls.push_back(&I);

          const Function *CF = CB->getCalledFunction();
          auto S = getOrInsertEEntryFunction(M, CF);
          auto EF = S.first;
          auto ID = S.second;

          if (A.isEExitCall(&I)) {
            // See remarks about the names of these variables in MSP430Sancus.h
            auto HV = newArrayVariable(
                M, getSecureLinkingHashName(&F, CF), getKeyByteSize());
            HV->setSection(getSecureLinkingSectionName(&F, CF));
            auto IV = 
              newSecretVariable(M, getSecureLinkingIdName(&F, CF), Int16Ty, &F);
            auto P1 = IRB.CreatePtrToInt(EF, Int16Ty);
            auto P2 = IRB.CreatePtrToInt(HV, Int16Ty);
            auto P3 = IRB.CreatePtrToInt(IV, Int16Ty);
            IRB.CreateCall(Intrinsic::getDeclaration(&M, 
                  Intrinsic::sllvm_attest), {P1, P2, P3});
          }

          SmallVector<Value *, 6> A {IRB.CreateLoad(ID)};
          A.insert(std::end(A), CB->arg_begin(), CB->arg_end());

          CallInst * CI = IRB.CreateCall(cast<FunctionType>(EF->getType()->getPointerElementType()), EF, A);
          CI->setCallingConv(CallingConv::SANCUS_ENTRY);
          I.replaceAllUsesWith(CI);
        }
      }
    }
  }

  for (auto I : ECalls) {
    // FIXME: See remark in MSP430SelLowering::lowerSancusCallResult() to
    //  understand why this basic block needs to be split.
    SplitBlock(I->getParent(), I);
    I->eraseFromParent();
  }
}

void SancusTransformation::handleStacklessEnclave(Module &M) {
  IRBuilder<> IRB(M.getContext());
  if (! hasStack(&M)) {
    for (Function& F : M) {
      if (getAnalysis<SLLVMAnalysis>().getResults().isEEntryDef(&F)) {
        assert(F.getBasicBlockList().size() == 1 && "TODO: Support more BBs");
        IRB.SetInsertPoint(&F.back().back());
        IRB.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::sllvm_rete));
      }
    }
  }
}

void SancusTransformation::handleEnclave(Module &M) {
  auto A = getAnalysis<SLLVMAnalysis>().getResults();

  // Globals
  for (auto GVI = M.global_begin(), E = M.global_end(); GVI != E; GVI++) {
    if (A.isEData(&*GVI)) {
      if (GVI->isConstant()) {
        GVI->setSection(getTextSectionName(&*GVI));
      }
      else {
        GVI->setSection(getDataSectionName(&*GVI));
      }
    }
  }

  // Functions
  for (Function& F : M) {
    if (! F.isDeclaration()) {
      if (A.isEEntryDef(&F) || A.isEFunc(&F)) {
        F.setSection(getTextSectionName(&F));
      }
    }
  }

  if (getAnalysis<SLLVMAnalysis>().getResults().isPM()) {
    createSancusModuleStruct(M);
    createDispatch(M);

    if (!hasFixedDataSection(&M)) {
      createGlobals(M);
    }

    if (! hasStack(&M)) {
      handleStacklessEnclave(M);
    }
  }
}

bool SancusTransformation::runOnModule(Module &M) {
  if (FixDataSection) {
    M.addModuleFlag(Module::Override, getFixDataSectionFlagName(), 1);
  }
  handleEnclave(M);
  handleCalls(M);

  Type * Int16Ty = Type::getInt16Ty(M.getContext());
  M.getOrInsertGlobal(getGLobalStackName(), Int16Ty);
  M.getOrInsertGlobal(global_pc, Int16Ty); // TODO: Remove

  return true; // TODO: Only return true when something changed
}

char SancusTransformation::ID = 0;

static RegisterPass<SancusTransformation> X(
    "sancus-transform", "Sancus transformation pass");

void SancusTransformation::getAnalysisUsage(AnalysisUsage &A) const {
  A.addRequired<SLLVMAnalysis>();
}
