#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/TargetFolder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/TypeBuilder.h"
#include "llvm/Support/Format.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/CFG.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/UnifyFunctionExitNodes.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/ADT/SetVector.h"

#include <string>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sstream>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <unordered_map>

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "CPSensitive"

typedef IRBuilder<true, TargetFolder> BuilderTy;
typedef std::pair<Value *, Instruction *> CEOType;

namespace {
	using namespace llvm;

	class CPSensitivePass : public ModulePass {
		public:
			static char ID;
			const DataLayout *DL;
			TargetLibraryInfo *TLI;
			AliasAnalysis *AA;

			std::unordered_set<Function*> AllFunctions;
			std::unordered_set<Function *> SensitiveFuncs;

			typedef DenseMap<Type*, bool> TypesProtectInfoTy;
			TypesProtectInfoTy StructTypesProtectInfo;

			typedef DenseMap<Value*, unordered_set<Function*> > IndirectCallMap;
			IndirectCallMap AllIndirectCalls;

			typedef DenseMap<Function*, vector<Value*>> Func2ValueMap;
			Func2ValueMap Func2RetValueMap;

			// all struct/union tbaa tag
			DenseMap<StructType*, MDNode*> StructsTBAA;
			DenseMap<StructType*, MDNode*> UnionsTBAA;

			// function's vararg/return is sensitive?
			typedef DenseMap<Function*, bool> FunctionAttrMap;
			FunctionAttrMap SensitiveVarargMap;
			FunctionAttrMap SensitiveReturnMap;

			// all sensitive values: instructions, arguments, globals
			std::unordered_set<Value*> AllSensitiveValues;

			void SensitiveFuncAnalysis(Module * M);
			MDString* getMDString(MDNode *TBAATag);

			bool valueWithSensitiveType(Value *V);
			bool isTypeSensitive(Type * ty);
			bool isValueSensitive(Value *V);

			bool addIfOneIsSensitive(Value *V1, Value *V2);
			bool addToSensitive(Value *V);
			bool addSecondIfFirstIsSensitive(Value *V1, Value *V2);
			bool addSecondIfFirstIsSensitive(Value *V1, vector<Value *> &V2);
			bool addValueIfReturnIsSensitive(Value *V, Function *F);

			bool isTypeMatch(ImmutableCallSite CS, Function *F, Type *ReturnType);


			// to handle recursive type, record the 'Visited'
			bool shouldProtectType(Type *Ty, std::unordered_set<Type*> &Visited, MDNode *TBAATag = NULL);

			void analyzeIndirectCalls(Module &M);
			void collectSensitiveTypes(Module &M);
			void dumpAllProtectedTypes();
			bool handleCallsite(ImmutableCallSite CS, Function *F);
			bool doTBAAOnFunction(llvm::Function &F);
			bool runOnModule(llvm::Module &M) override;

			void getAnalysisUsage(AnalysisUsage &AU) const override {
				AU.addRequired<DataLayoutPass>();
				AU.addRequired<TargetLibraryInfo>();
				AU.addRequired<AliasAnalysis>();
			}

			CPSensitivePass() : ModulePass(ID) {}

		private:
			BuilderTy *Builder;
			// remember all BB with instrumentation for PHINodes
			std::unordered_set<PHINode *> allInstrumentedPHINodes;
			std::unordered_map<BasicBlock *, int> allInstrumentedBBs;
			// for each basic block, we assign an ID to it. It starts from 0, to 100000
			uint64_t BBID;
			std::unordered_set<Function *> functionNoRet;

			void findConstantExpr(Instruction * I);
			void replaceCEOWithInstr(Instruction * I, Value * pointer);
			void ConstantExpr2Instruction(Module &M);
			// only one call to ptwrite, can dump 12 bits value
			bool insertPTWrite(Module &M, Value * value, 
					BasicBlock::iterator insertPoint);
			// two calls to ptwrites, can dump 24 bits value. The values are added with 4K 
			bool insertPTWriteAdd4K(Module &M, Value * value, 
					BasicBlock::iterator insertPoint);
			bool insertPTWriteCallToBB(Module &M, BasicBlock * BB);
			void addSensitiveCallIn(Module &M);
			void revokeSensitivity(Module &M);
			bool hasSensitiveUses(Instruction * I);
			bool hasSensitiveInstrs(Function * func);
			void splitBBAfterCall(Module &M);
			void doInstrumentation(Module &M);
			void doShiftIndirectCall(Module &M);

			bool pointToI8(Type * type);
			void _hasSensitiveUses(Instruction * I, std::unordered_set<Instruction *> &visited, bool &ret);
			void _hasSensitiveInstrs(Function * func, std::unordered_set<Function *> &visited, bool &ret);

			unsigned long getIDFromBB(BasicBlock * BB);
			unsigned long getIDFromPTWriteInstr(Instruction * I);
	};
}
