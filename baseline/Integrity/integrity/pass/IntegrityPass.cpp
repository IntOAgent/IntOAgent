/**
 * IntegrityPass.cpp
 *
 * LLVM Legacy FunctionPass implementing the "Integrity" instrumentation from:
 *   "Integrity: Finding Integer Errors by Targeted Fuzzing" (NDSS/CCS)
 *
 * For each arithmetic operation (Add, Sub, Mul, Shl, SDiv, UDiv, SRem, URem)
 * we insert a "guard branch" that calls __integrity_report() on error,
 * then falls through (continue-on-error semantics).
 *
 * Build:
 *   clang++-14 -shared -fPIC -fno-rtti $(llvm-config-14 --cxxflags) \
 *              -o build/IntegrityPass.so pass/IntegrityPass.cpp -lLLVM-14
 *
 * Use:
 *   opt-14 -enable-new-pm=0 -load build/IntegrityPass.so -integrity \
 *          -o foo.bc foo.pre.bc
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Pass.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/APInt.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/MDBuilder.h"

#include <fstream>
#include <set>
#include <string>

using namespace llvm;

// Error codes matching runtime library
enum IntegrityErrorCode {
  ERR_OVERFLOW   = 1,
  ERR_UNDERFLOW  = 2,
  ERR_DIV_ZERO   = 3,
  ERR_SHIFT_OVF  = 4,
  ERR_MININT_NEG1 = 5,
};

namespace {

struct IntegrityPass : public FunctionPass {
  static char ID;

  // Runtime report function: void __integrity_report(i8*, i32, i32, i32)
  FunctionCallee ReportFn;

  // Counter for __libfuzzer_extra_counters globals
  unsigned GuardIdx = 0;

  // Guard branch source locations collected during this module's instrumentation.
  // Written to $INTEGRITY_OUTDIR/BBtargets.txt in doFinalization() so that
  // AFLGo can use them as directed-fuzzing target sites.
  std::set<std::string> GuardLocations;

  IntegrityPass() : FunctionPass(ID) {}

  // -----------------------------------------------------------------------
  // Module initialization: declare the runtime function
  // -----------------------------------------------------------------------
  bool doInitialization(Module &M) override {
    LLVMContext &Ctx = M.getContext();
    Type *VoidTy  = Type::getVoidTy(Ctx);
    Type *I8PtrTy = Type::getInt8PtrTy(Ctx);
    Type *I32Ty   = Type::getInt32Ty(Ctx);

    FunctionType *FT = FunctionType::get(
        VoidTy, {I8PtrTy, I32Ty, I32Ty, I32Ty}, /*isVarArg=*/false);
    ReportFn = M.getOrInsertFunction("__integrity_report", FT);
    return true;
  }

  // -----------------------------------------------------------------------
  // Helper: create a __libfuzzer_extra_counters global (uint8_t).
  //
  // MUST use InternalLinkage: each translation unit compiled separately
  // generates its own guard_0, guard_1, … If we used ExternalLinkage,
  // linking multiple .o files would produce "multiple definition" errors.
  // With InternalLinkage (i.e. 'static' in C), each TU's globals are
  // independent; the linker merges the __libfuzzer_extra_counters *section*
  // into one contiguous range that LibFuzzer discovers at startup.
  // -----------------------------------------------------------------------
  GlobalVariable *createExtraCounter(Module &M) {
    LLVMContext &Ctx = M.getContext();
    Type *I8Ty = Type::getInt8Ty(Ctx);
    auto *GV = new GlobalVariable(
        M, I8Ty, /*isConstant=*/false,
        GlobalValue::InternalLinkage,          // <-- internal (was External)
        ConstantInt::get(I8Ty, 0),
        "__integrity_guard_" + std::to_string(GuardIdx++));
    GV->setSection("__libfuzzer_extra_counters");
    GV->setAlignment(Align(1));
    return GV;
  }

  // -----------------------------------------------------------------------
  // Helper: emit __integrity_report(file, line, col, errcode) call
  // -----------------------------------------------------------------------
  void emitReport(IRBuilder<> &B, Instruction *Orig, int ErrCode) {
    Module *M = Orig->getModule();
    LLVMContext &Ctx = M->getContext();

    // Source location from debug info
    const DebugLoc &DL = Orig->getDebugLoc();
    unsigned Line = DL ? DL.getLine() : 0;
    unsigned Col  = DL ? DL.getCol()  : 0;

    // Get filename from debug info or module name
    std::string Filename = M->getSourceFileName();
    if (DL) {
      if (auto *Scope = dyn_cast_or_null<DIScope>(DL.getScope()))
        Filename = Scope->getFilename().str();
    }

    Value *FileStr = B.CreateGlobalStringPtr(Filename, "integrity.file");
    Value *LineVal = ConstantInt::get(Type::getInt32Ty(Ctx), Line);
    Value *ColVal  = ConstantInt::get(Type::getInt32Ty(Ctx), Col);
    Value *ErrVal  = ConstantInt::get(Type::getInt32Ty(Ctx), ErrCode);

    B.CreateCall(ReportFn, {FileStr, LineVal, ColVal, ErrVal});

    // Record this guard location for AFLGo BBtargets.txt.
    // Use only the basename so it matches AFLGo's BBnames.txt format.
    if (Line > 0 && !Filename.empty()) {
      std::size_t slash = Filename.find_last_of("/\\");
      std::string base = (slash != std::string::npos) ? Filename.substr(slash + 1) : Filename;
      GuardLocations.insert(base + ":" + std::to_string(Line));
    }

    // Increment the libfuzzer extra counter to signal this guard was taken
    GlobalVariable *GV = createExtraCounter(*M);
    Value *Loaded = B.CreateLoad(Type::getInt8Ty(Ctx), GV);
    Value *Incr   = B.CreateAdd(Loaded, ConstantInt::get(Type::getInt8Ty(Ctx), 1));
    B.CreateStore(Incr, GV);
  }

  // -----------------------------------------------------------------------
  // Helper: insert a one-sided guard branch.
  // Returns the instruction to insert AFTER (first instr of tail BB).
  // -----------------------------------------------------------------------
  Instruction *insertGuardBranch(Value *Cond, Instruction *InsertBefore,
                                  Instruction *OrigInst, int ErrCode) {
    Module *M = InsertBefore->getModule();
    LLVMContext &Ctx = M->getContext();

    // Branch weights: very unlikely to take the guard branch
    MDBuilder MDB(Ctx);
    MDNode *Weights = MDB.createBranchWeights(1, 1000000);

    // Split: creates ThenBB -> TailBB
    Instruction *ThenTerm = SplitBlockAndInsertIfThen(
        Cond, InsertBefore, /*Unreachable=*/false, Weights);

    // Insert report call in ThenBB (before ThenTerm)
    IRBuilder<> ThenB(ThenTerm);
    emitReport(ThenB, OrigInst, ErrCode);

    // Return first instruction of TailBB (the block after ThenBB)
    return ThenTerm->getSuccessor(0)->getFirstNonPHI();
  }

  // -----------------------------------------------------------------------
  // Sign/width inference
  // -----------------------------------------------------------------------
  bool isSigned(BinaryOperator *BO) {
    unsigned Width = BO->getType()->getIntegerBitWidth();
    if (Width >= 32) {
      // Use NSW/NUW flags when present
      if (BO->hasNoSignedWrap())   return true;
      if (BO->hasNoUnsignedWrap()) return false;
      // Default: treat 32/64-bit as signed
      return true;
    }
    // Narrow types: check if operands come from sign extension
    for (Value *Op : BO->operands()) {
      if (isa<SExtInst>(Op)) return true;
      if (isa<ZExtInst>(Op)) return false;
    }
    return true; // default signed
  }

  unsigned inferWidth(BinaryOperator *BO) {
    unsigned NativeWidth = BO->getType()->getIntegerBitWidth();
    // If result is truncated, use narrower width
    for (User *U : BO->users()) {
      if (auto *TI = dyn_cast<TruncInst>(U))
        return TI->getType()->getIntegerBitWidth();
    }
    return NativeWidth;
  }

  // -----------------------------------------------------------------------
  // Instrument Add / Sub / Mul via promotion
  // -----------------------------------------------------------------------
  void instrumentAddSubMul(BinaryOperator *BO, Instruction *&InsertPt) {
    unsigned Opcode = BO->getOpcode();
    bool Signed = isSigned(BO);
    unsigned Width = inferWidth(BO);

    // Determine promotion width
    unsigned WiderWidth;
    if      (Width <= 8)  WiderWidth = 16;
    else if (Width <= 16) WiderWidth = 32;
    else if (Width <= 32) WiderWidth = 64;
    else                  WiderWidth = 128;

    // Instrumentation reduction rules (paper §III.D):
    // - Skip unsigned Sub underflow (covered by overflow detection)
    if (Opcode == Instruction::Sub && !Signed) return;

    // Check constant operand optimizations
    if (Opcode == Instruction::Add || Opcode == Instruction::Sub) {
      // Skip overflow check for Add with negative constant
      // Skip underflow check for Add with positive constant
      Value *RHS = BO->getOperand(1);
      if (auto *CI = dyn_cast<ConstantInt>(RHS)) {
        if (Signed) {
          bool IsNeg = CI->isNegative();
          if (Opcode == Instruction::Add && IsNeg) {
            // Adding negative: can only underflow, not overflow — skip overflow
            // We'll still check underflow below
          }
        }
      }
    }

    // Skip x*x underflow (squares are always non-negative)
    if (Opcode == Instruction::Mul && Signed) {
      if (BO->getOperand(0) == BO->getOperand(1)) {
        // x*x: no underflow possible
        // Still check overflow
      }
    }

    LLVMContext &Ctx = BO->getContext();
    Module *M = BO->getModule();

    Type *NativeTy = IntegerType::get(Ctx, Width);
    Type *WiderTy  = IntegerType::get(Ctx, WiderWidth);

    IRBuilder<> B(InsertPt);

    // Get original operands (truncated to native width if needed)
    Value *LHS = BO->getOperand(0);
    Value *RHS = BO->getOperand(1);

    // Truncate to native width if operands are wider (e.g., for narrow ops)
    if (LHS->getType()->getIntegerBitWidth() > Width)
      LHS = B.CreateTrunc(LHS, NativeTy, "lhs.narrow");
    if (RHS->getType()->getIntegerBitWidth() > Width)
      RHS = B.CreateTrunc(RHS, NativeTy, "rhs.narrow");

    // Promote to wider type
    Value *WLhs, *WRhs;
    if (Signed) {
      WLhs = B.CreateSExt(LHS, WiderTy, "wlhs");
      WRhs = B.CreateSExt(RHS, WiderTy, "wrhs");
    } else {
      WLhs = B.CreateZExt(LHS, WiderTy, "wlhs");
      WRhs = B.CreateZExt(RHS, WiderTy, "wrhs");
    }

    // Compute in wider type
    Value *WResult;
    switch (Opcode) {
      case Instruction::Add: WResult = B.CreateAdd(WLhs, WRhs, "wadd"); break;
      case Instruction::Sub: WResult = B.CreateSub(WLhs, WRhs, "wsub"); break;
      case Instruction::Mul: WResult = B.CreateMul(WLhs, WRhs, "wmul"); break;
      default: return;
    }

    // Build bound checks
    if (Signed) {
      APInt MaxVal = APInt::getSignedMaxValue(Width).sext(WiderWidth);
      APInt MinVal = APInt::getSignedMinValue(Width).sext(WiderWidth);

      Value *MaxConst = ConstantInt::get(WiderTy, MaxVal);
      Value *MinConst = ConstantInt::get(WiderTy, MinVal);

      // Overflow: WResult > INT_MAX_narrow
      Value *OvfCond = B.CreateICmpSGT(WResult, MaxConst, "ovf.cond");
      InsertPt = insertGuardBranch(OvfCond, InsertPt, BO, ERR_OVERFLOW);

      // Rebuild builder at new insert point
      IRBuilder<> B2(InsertPt);

      // Underflow: WResult < INT_MIN_narrow
      // Skip for x*x (squares can't underflow)
      bool IsSquare = (Opcode == Instruction::Mul &&
                       BO->getOperand(0) == BO->getOperand(1));
      if (!IsSquare) {
        // Skip underflow for Add with a positive constant
        bool SkipUnderflow = false;
        if (Opcode == Instruction::Add) {
          if (auto *CI = dyn_cast<ConstantInt>(BO->getOperand(1)))
            if (!CI->isNegative()) SkipUnderflow = true;
        }
        // Skip overflow for Add with a negative constant (already done above)
        if (Opcode == Instruction::Sub) {
          // For subtraction: underflow when result < INT_MIN
          // No special skipping
        }
        if (!SkipUnderflow) {
          Value *UndCond = B2.CreateICmpSLT(WResult, MinConst, "und.cond");
          InsertPt = insertGuardBranch(UndCond, InsertPt, BO, ERR_UNDERFLOW);
        }
      }
    } else {
      // Unsigned: only overflow (result > UINT_MAX_narrow)
      APInt MaxVal = APInt::getMaxValue(Width).zext(WiderWidth);
      Value *MaxConst = ConstantInt::get(WiderTy, MaxVal);

      Value *OvfCond = B.CreateICmpUGT(WResult, MaxConst, "ovf.cond");
      InsertPt = insertGuardBranch(OvfCond, InsertPt, BO, ERR_OVERFLOW);
    }
  }

  // -----------------------------------------------------------------------
  // Instrument Shl (left shift)
  // -----------------------------------------------------------------------
  void instrumentShift(BinaryOperator *BO, Instruction *&InsertPt) {
    LLVMContext &Ctx = BO->getContext();
    Module *M = BO->getModule();
    bool Signed = isSigned(BO);
    unsigned Width = BO->getType()->getIntegerBitWidth();

    Value *X = BO->getOperand(0); // value being shifted
    Value *N = BO->getOperand(1); // shift amount

    IRBuilder<> B(InsertPt);

    Type *Ty    = IntegerType::get(Ctx, Width);
    Value *Zero = ConstantInt::get(Ty, 0);
    Value *WidthVal = ConstantInt::get(Ty, Width);

    // Check 1: shift amount >= width (always undefined)
    Value *ShiftTooBig = B.CreateICmpUGE(N, WidthVal, "shift.toobig");
    InsertPt = insertGuardBranch(ShiftTooBig, InsertPt, BO, ERR_SHIFT_OVF);
    IRBuilder<> B2(InsertPt);

    // For signed shifts: skip if x < 0 (UB anyway; paper skips this check)
    if (Signed) {
      Value *XNeg = B2.CreateICmpSLT(X, Zero, "x.neg");
      // We only check hp(x) + n >= width-1 when x >= 0
      // Use llvm.ctlz to compute highest set bit position
      // hp(x) = Width - 1 - clz(x)  (for x > 0)
      // Error if hp(x) + N >= Width-1, i.e., N >= Width-1 - hp(x) = clz(x)
      // So: N >= clz(x) means overflow

      Function *CtlzFn = Intrinsic::getDeclaration(
          M, Intrinsic::ctlz, {Ty});
      Value *IsZeroUndef = ConstantInt::get(Type::getInt1Ty(Ctx), 0);
      Value *Clz = B2.CreateCall(CtlzFn, {X, IsZeroUndef}, "clz");

      // If x == 0, clz = Width, shift is safe. So check N >= clz only when x > 0
      Value *XPos = B2.CreateICmpSGT(X, Zero, "x.pos");
      Value *ShiftOvf = B2.CreateICmpUGE(N, Clz, "shift.ovf");
      Value *SignedOvf = B2.CreateAnd(XPos, ShiftOvf, "signed.ovf");

      InsertPt = insertGuardBranch(SignedOvf, InsertPt, BO, ERR_SHIFT_OVF);
    } else {
      // Unsigned: check if N >= clz(x), meaning we shift out set bits
      Function *CtlzFn = Intrinsic::getDeclaration(
          M, Intrinsic::ctlz, {Ty});
      Value *IsZeroUndef = ConstantInt::get(Type::getInt1Ty(Ctx), 0);
      Value *Clz = B2.CreateCall(CtlzFn, {X, IsZeroUndef}, "clz");

      Value *XNonZero = B2.CreateICmpNE(X, Zero, "x.nonzero");
      Value *ShiftOvf = B2.CreateICmpUGE(N, Clz, "shift.ovf");
      Value *UnsignedOvf = B2.CreateAnd(XNonZero, ShiftOvf, "unsigned.ovf");

      InsertPt = insertGuardBranch(UnsignedOvf, InsertPt, BO, ERR_SHIFT_OVF);
    }
  }

  // -----------------------------------------------------------------------
  // Instrument SDiv / UDiv / SRem / URem
  //
  // IMPORTANT: Guards run BEFORE the division to prevent a real SIGFPE.
  // We replace the divisor with a safe value (1) when it would cause UB,
  // so the division always executes without trapping — continue-on-error.
  // -----------------------------------------------------------------------
  void instrumentDivRem(BinaryOperator *BO, Instruction *&InsertPt) {
    LLVMContext &Ctx = BO->getContext();
    unsigned Opcode = BO->getOpcode();
    bool IsSigned = (Opcode == Instruction::SDiv || Opcode == Instruction::SRem);
    unsigned Width = BO->getType()->getIntegerBitWidth();

    Value *Dividend = BO->getOperand(0);
    Value *Divisor  = BO->getOperand(1);

    Type *Ty    = IntegerType::get(Ctx, Width);
    Value *Zero = ConstantInt::get(Ty, 0);
    Value *One  = ConstantInt::get(Ty, 1);

    // All condition checks are inserted BEFORE BO (before the division).
    IRBuilder<> B(BO);

    // Check: divisor == 0
    Value *DivZero = B.CreateICmpEQ(Divisor, Zero, "divzero.cond");
    Value *IsUnsafe = DivZero;

    Value *MinIntNeg1 = nullptr;
    if (IsSigned) {
      APInt MinInt = APInt::getSignedMinValue(Width);
      Value *MinConst    = ConstantInt::get(Ty, MinInt);
      Value *NegOneConst = ConstantInt::get(Ty, APInt::getAllOnesValue(Width));
      Value *IsMinInt    = B.CreateICmpEQ(Dividend, MinConst, "isminint");
      Value *IsNegOne    = B.CreateICmpEQ(Divisor, NegOneConst, "isnegone");
      MinIntNeg1 = B.CreateAnd(IsMinInt, IsNegOne, "minint.neg1");
      IsUnsafe = B.CreateOr(DivZero, MinIntNeg1, "is.unsafe");
    }

    // Replace divisor with 1 when unsafe: prevents actual SIGFPE while we
    // report the error and continue.
    Value *SafeDivisor = B.CreateSelect(IsUnsafe, One, Divisor, "safe.div");
    BO->setOperand(1, SafeDivisor);

    // Insert guard branches BEFORE BO (it gets moved to TailBB after split).
    // Guard 1: divisor == 0
    insertGuardBranch(DivZero, BO, BO, ERR_DIV_ZERO);
    // After split, BO is in TailBB. Both BO and MinIntNeg1 are accessible
    // there since the pre-split block dominates TailBB.

    // Guard 2: INT_MIN / -1 (signed only)
    if (IsSigned && MinIntNeg1) {
      insertGuardBranch(MinIntNeg1, BO, BO, ERR_MININT_NEG1);
    }

    // Update InsertPt to after BO (BO is now in its final TailBB)
    if (BO->getNextNode())
      InsertPt = BO->getNextNode();
  }

  // -----------------------------------------------------------------------
  // Module finalization: write BBtargets.txt for AFLGo directed fuzzing.
  //
  // When INTEGRITY_OUTDIR is set, append each guard branch's source location
  // (basename:line) to $INTEGRITY_OUTDIR/BBtargets.txt.  AFLGo's preprocessing
  // pass reads this file and computes distances from every BB to these targets,
  // directing the fuzzer toward inputs that trigger arithmetic errors.
  //
  // Append (not overwrite): multiple TUs compiled in sequence each add their
  // own entries.  The build script should delete BBtargets.txt before starting
  // a fresh build.
  // -----------------------------------------------------------------------
  bool doFinalization(Module &) override {
    const char *OutDir = getenv("INTEGRITY_OUTDIR");
    if (OutDir && !GuardLocations.empty()) {
      std::string TargetsFile = std::string(OutDir) + "/BBtargets.txt";
      std::ofstream F(TargetsFile, std::ios::app);
      if (F.is_open()) {
        for (const auto &Loc : GuardLocations)
          F << Loc << "\n";
      }
    }
    GuardLocations.clear();
    return false;
  }

  // -----------------------------------------------------------------------
  // Main pass: runOnFunction
  // -----------------------------------------------------------------------
  bool runOnFunction(Function &F) override {
    // Collect all binary operators first to avoid iterator invalidation
    SmallVector<BinaryOperator *, 64> WorkList;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          unsigned Op = BO->getOpcode();
          // Only instrument integer operations
          if (!BO->getType()->isIntegerTy()) continue;
          switch (Op) {
            case Instruction::Add:
            case Instruction::Sub:
            case Instruction::Mul:
            case Instruction::Shl:
            case Instruction::SDiv:
            case Instruction::UDiv:
            case Instruction::SRem:
            case Instruction::URem:
              WorkList.push_back(BO);
              break;
            default:
              break;
          }
        }
      }
    }

    bool Changed = false;
    for (BinaryOperator *BO : WorkList) {
      // InsertPt starts as the instruction AFTER BO
      // We use the next instruction in the (possibly split) BB
      Instruction *InsertPt = BO->getNextNode();
      if (!InsertPt) continue; // BO is a terminator? shouldn't happen

      unsigned Op = BO->getOpcode();
      switch (Op) {
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
          instrumentAddSubMul(BO, InsertPt);
          Changed = true;
          break;
        case Instruction::Shl:
          instrumentShift(BO, InsertPt);
          Changed = true;
          break;
        case Instruction::SDiv:
        case Instruction::UDiv:
        case Instruction::SRem:
        case Instruction::URem:
          instrumentDivRem(BO, InsertPt);
          Changed = true;
          break;
        default:
          break;
      }
    }

    return Changed;
  }
};

} // anonymous namespace

char IntegrityPass::ID = 0;

static RegisterPass<IntegrityPass> X(
    "integrity",
    "Integrity: Integer Error Detection via Guard Branches",
    /*CFGOnly=*/false,
    /*isAnalysis=*/false);
