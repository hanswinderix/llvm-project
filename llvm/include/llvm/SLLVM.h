#ifndef SLLVM_H
#define SLLVM_H

#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallString.h"

using namespace llvm;

namespace sllvm {

  constexpr const char* prefix = "sllvm";
  constexpr const char* separator = "_";
  constexpr const char* module_flag_pm = "sllvm-protected-module";
  constexpr const char* attribute_eentry = "sllvm-eentry";
  constexpr const char* attribute_efunc = "sllvm-efunc";
  constexpr const char* attribute_edata = "sllvm-edata";

  inline bool isPM(const Module *M) {
    return M->getModuleFlag(module_flag_pm) != nullptr;
  }

  // TODO: This function will become obsolete once we give up on the idea
  //       that there is Module that represents a protected module. This
  //       restriction is no longer valid when we want to support
  //       multi-protection domain Modules.
  inline const StringRef getPMName(const Module *M) {
    assert(isPM(M));
    // TODO: Is the the right way to do this ?
    return cast_or_null<MDString>(M->getModuleFlag(module_flag_pm))->getString();
  }

  inline bool isEEntry(const Function *F) {
    return F->hasFnAttribute(attribute_eentry);
  }

  inline bool isEFunc(const Function *F) {
    return F->hasFnAttribute(attribute_efunc);
  }

  inline bool isEData(const GlobalVariable *GV) {
    return GV->hasAttribute(attribute_edata);
  }

  inline bool isProtected(const Function *F) {
    return isEFunc(F) || isEEntry(F);
  }

  inline bool isProtected(const GlobalVariable *GV) {
    return isEData(GV);
  }

  inline const StringRef getProtectionDomain(const Module *M) {
    if (isPM(M)) {
      return getPMName(M);
    }

    return {};
  }

  inline const StringRef getProtectionDomain(const GlobalVariable *GV) {
    return GV->getAttribute(attribute_edata).getValueAsString();
  }

  inline const StringRef getProtectionDomain(const Function * F) {
    if (F->hasFnAttribute(attribute_eentry)) {
      return F->getFnAttribute(attribute_eentry).getValueAsString();
    } 
    if (F->hasFnAttribute(attribute_efunc)) {
      return F->getFnAttribute(attribute_efunc).getValueAsString();
    }

    return {};
  }

  template<typename T, typename U>
  inline bool shareProtectionDomains(const T V1, const U V2) {
    return getProtectionDomain(V1).compare(getProtectionDomain(V2)) == 0;
  }
}

#endif
