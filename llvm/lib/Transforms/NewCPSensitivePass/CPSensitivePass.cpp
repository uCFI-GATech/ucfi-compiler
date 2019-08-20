#include "CPSensitivePass.h"

using namespace llvm;
using namespace std;

static const char* IgnoreFuncs[] = {
	// c functions
	"__cxa_atexit", 
	"realloc", "free", "obstack_free", 
	"printf", "sprintf", "vsprintf", "fprintf", "vfprintf", 
	"read", "puts", "scanf", "fread", "fgets", "fputs", "fwrite", "sscanf",
	"memchr", "memcmp", 
	"strlen", "strchr", "strtoul", "strcmp", "strncmp", "strcpy", "strncpy", 
	"strrchr", "strcat", "strtol", "strpbrk", "strstr", "strcspn", "strspn",
	"strerror", "strtok", "strtod",
	"bsearch", "remove", "getenv",
	// c++ functions
	"_ZdlPv", "_ZdaPv", 
	"__cxa_begin_catch", "_ZSt20__throw_length_errorPKc", "__cxa_free_exception",
	"_cxa_throw", "__dynamic_cast", 
	// the end
	nullptr
};

static const char* PropagateArgFuncs[] = {
	"memcpy",
	"llvm.memcpy",
	nullptr,
};

void saveModule(Module &M, Twine filename)
{
	int ll_fd;
	sys::fs::openFileForWrite(filename + "_pt.ll", ll_fd, 
			sys::fs::F_RW | sys::fs::F_Text);
	raw_fd_ostream ll_file(ll_fd, true, true);
	M.print(ll_file, nullptr);

	int bc_fd;
	sys::fs::openFileForWrite(filename + "_pt.bc", bc_fd, 
			sys::fs::F_RW | sys::fs::F_Text);
	raw_fd_ostream bc_file(bc_fd, true, true);
	WriteBitcodeToFile(&M, bc_file);
}

static MDNode *getNextElTBAATag(size_t &STBAAIndex, Type *ElTy, const StructLayout *SL,
		unsigned idx, MDNode *STBAATag) {

	if (ElTy->isSingleValueType() && STBAATag) {
		size_t Off = SL->getElementOffset(idx);
		size_t STBAASize = STBAATag->getNumOperands();

		// skip over embedded structs (if any)		
		while (STBAAIndex+2 < STBAASize &&
				cast<ConstantInt>(cast<ValueAsMetadata>(STBAATag->getOperand(STBAAIndex))->getValue())->getValue().ult(Off)) {
			STBAAIndex += 3;
		}

		if (STBAAIndex+2 < STBAASize &&
				cast<ConstantInt>(cast<ValueAsMetadata>(STBAATag->getOperand(STBAAIndex))->getValue())->equalsInt(Off)) {

			// The struct type might be union, in which case we'll have >1 tags
			// for the same offset.
			if (STBAAIndex+3+2 < STBAASize && 
					cast<ConstantInt>(cast<ValueAsMetadata>(STBAATag->getOperand(STBAAIndex+3))->getValue())->equalsInt(Off)) {
				//FIXME: support unions	
			} else {
				//FIXME: the following assertion seems to not hold for bitfields
				//assert(cast<ConstantInt>(STBAATag->getOperand(STBAAIndex+1))
				//	->equalsInt(DL->getTypeAllocSize(ElTy)));
				if (STBAATag->getOperand(STBAAIndex+2) != NULL) {
					return cast<MDNode>(STBAATag->getOperand(STBAAIndex+2));
				}
			}
		}
	}
	return NULL;
}

MDString* CPSensitivePass::getMDString(MDNode *TBAATag) {
	if (!TBAATag || TBAATag->getNumOperands() <= 1)
		return nullptr;

	MDString *TagName = dyn_cast<MDString>(TBAATag->getOperand(0));
	if (TagName)
		return TagName;

	MDNode *TBAATag2 = dyn_cast<MDNode>(TBAATag->getOperand(0));
	if (!TBAATag2 || TBAATag2->getNumOperands() <= 1)
		return nullptr;

	TagName = dyn_cast<MDString>(TBAATag2->getOperand(0));
	return TagName;
}

bool CPSensitivePass::isTypeSensitive(Type * ty) {
	TypesProtectInfoTy::key_type key(ty);
	
	TypesProtectInfoTy::iterator it = StructTypesProtectInfo.find(key);
	if (it == StructTypesProtectInfo.end()) {
		std::unordered_set<Type*> Visited;
		shouldProtectType(ty, Visited, nullptr);
		it = StructTypesProtectInfo.find(key);
		if (it == StructTypesProtectInfo.end()) {
			errs() << "cannot find type " << *ty << '\n';
		}
	}	
	assert(it != StructTypesProtectInfo.end() && "cannot find type");
	return it->second;
}

bool CPSensitivePass::valueWithSensitiveType(Value* V) {
	return isTypeSensitive(V->getType());
}

bool CPSensitivePass::isValueSensitive(Value* V) {
	if (AllSensitiveValues.find(V) != AllSensitiveValues.end())
		return true;
	else
		return false;
}

bool CPSensitivePass::addToSensitive(Value * V) {
	if (!isa<ConstantPointerNull>(V)) {
		if (AllSensitiveValues.insert(V).second) {
			//if (!isa<Function>(V))
			//	errs() << *V << "\n";
			return true;
		} else
			return false;
	} else
		return false;
}

/////////////    APIs    ////////////////////////////////////////////

bool CPSensitivePass::addIfOneIsSensitive(Value* V1, Value* V2) {

	if (isValueSensitive(V1)) {
		return addToSensitive(V2);
	} else if (isValueSensitive(V2)) {
		return addToSensitive(V1);
	} else
		return false;
}

bool CPSensitivePass::addSecondIfFirstIsSensitive(Value *V1, Value *V2) {

	if (isValueSensitive(V1)) {
		return addToSensitive(V2);
	}

	return false;
}

bool CPSensitivePass::addSecondIfFirstIsSensitive(Value *V1, vector<Value *> &V2) {

	if (!isValueSensitive(V1))
		return false;

	bool ret = false;

	for (auto value : V2) {
		ret |= addToSensitive(value);
	}

	return ret;
}

bool CPSensitivePass::addValueIfReturnIsSensitive(Value *V, Function *F) {
	if (F->getReturnType()->isPointerTy()) {
		if (SensitiveReturnMap[F]) {
			if (!isValueSensitive(V)) {
				return addToSensitive(V);
			}
		}
	}
	return false;
}

bool CPSensitivePass::isTypeMatch(ImmutableCallSite CS, Function *F, Type *ReturnType) {
	Function::const_arg_iterator fItr = F->arg_begin();
	ImmutableCallSite::arg_iterator aItr = CS.arg_begin();

	if (ReturnType != F->getReturnType())
		return false;

	while (fItr != F->arg_end() && aItr != CS.arg_end()) {
		Argument *formal = const_cast<Argument*> (&(*fItr));
		Value *actual = *aItr;
		if (formal->getType() != actual->getType())
			return false;

		++fItr;
		++aItr;
	}

	if (fItr == F->arg_end() && aItr == CS.arg_end())
		return true;
	
	return false;
}

// find all possible targets for indirect calls
void CPSensitivePass::analyzeIndirectCalls(Module &M) {
	// collect all address-taken functions
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
		Function &f = *it;
		if (f.hasAddressTaken())
			AllFunctions.insert(&f);
	}

	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
		Function &f = *it;
		if (f.isDeclaration() || f.isIntrinsic()) {
			continue;
		}

		for (inst_iterator ii = inst_begin(f), ie = inst_end(f);
				ii != ie; ++ii) {
			Instruction *inst = &(*ii);
			if (CallInst *cInst = dyn_cast<CallInst>(inst)) {
				if(!(cInst->getCalledFunction())) {
					std::unordered_set<Function*> &targets = 
						AllIndirectCalls[cInst->getCalledValue()];
					for (Function *tmpF : AllFunctions) {
						if (isTypeMatch(ImmutableCallSite(cInst), tmpF, inst->getType()))
							targets.insert(tmpF);
					}
				}
			} else if (InvokeInst *iInst = dyn_cast<InvokeInst>(inst)) {
				if (!(iInst->getCalledFunction())) {
					std::unordered_set<Function*> &targets = 
						AllIndirectCalls[iInst->getCalledValue()];
					for (Function *tmpF : AllFunctions) {
						if (isTypeMatch(ImmutableCallSite(iInst), tmpF, inst->getType()))
							targets.insert(tmpF);
					}
				}
			}
		}
	}
}

/**
 * 1. vtable pointer
 * 2. function pointer
 * 3. struct/union contains 1/2
 */
bool CPSensitivePass::shouldProtectType(Type *Ty, std::unordered_set<Type*> &Visited, MDNode *TBAATag) {
	// if the type has been checked before
	TypesProtectInfoTy::key_type key(Ty);
	TypesProtectInfoTy::iterator it = StructTypesProtectInfo.find(key);
	if (it != StructTypesProtectInfo.end() && !TBAATag) {
		return it->second;
	}


	// function
	if (Ty->isFunctionTy()) {
		StructTypesProtectInfo[key] = true;
		return true;
	}

	// primitive type
	if (Ty->getTypeID() <= Type::X86_MMXTyID  //the isPrimitiveType is removed in 3.6, use 'X86_MMXTyID'
			|| Ty->isIntegerTy()) {
		StructTypesProtectInfo[key] = false;
		return false;
	}

	// whether the tbaatag is function pointer or vtable pointer
	if (TBAATag && TBAATag->getNumOperands() > 1)  {
		MDString *TagName = getMDString(TBAATag);
		if (TagName) {
			if (TagName->getString() == "vtable pointer" ||
					TagName->getString() == "function pointer") {
				StructTypesProtectInfo[key] = true;
				return true;
			}
		}
	}

	// strip pointer
	Type* elemType = Ty;
	while (elemType->isPointerTy()) {
		PointerType *tmpType = dyn_cast<PointerType>(elemType);
		elemType = tmpType->getElementType();
	}

	// recursive type
	if (Visited.find(elemType) != Visited.end())
		return false;

	if (elemType->isFunctionTy()) {
		StructTypesProtectInfo[key] = true;
		return true;
	}

	// struct type or union type
	if (SequentialType *sTy = dyn_cast<SequentialType>(elemType)) {
		Visited.insert(sTy);
		bool isSensitive = shouldProtectType(sTy->getElementType(), Visited);
		StructTypesProtectInfo[key] = isSensitive;
		return isSensitive;
	} else if (StructType *sTy = dyn_cast<StructType>(elemType)) {
		// opaque type, false
		if (sTy->isOpaque()) {
			StructTypesProtectInfo[key] = false;
			return false;
		}

	// FIXME: for unknown reason, clang sometimes generates function pointer
	// items in structs as {}* (e.g., in struct _citrus_iconv_ops). However,
	// clang keeps correct TBAA tags even in such cases, so we look at it first.
		if (sTy->getNumElements() == 0 && TBAATag && TBAATag->getNumOperands() > 1) {
		MDString *TagName = getMDString(TBAATag);
		if (TagName && TagName->getString() == "function pointer") {
				StructTypesProtectInfo[key] = true;
				return true;
			}
		}
		
		// union type
		if (MDNode *UTBAATag = UnionsTBAA.lookup(sTy)) {
			// This is a union, try casting it to all components
			for (unsigned i = 0, e = UTBAATag->getNumOperands(); i+1 < e; i += 2) {
				if (!(UTBAATag->getOperand(i) && UTBAATag->getOperand(i+1))) {
					continue;
				}

				assert(isa<ValueAsMetadata>(UTBAATag->getOperand(i)));
				assert(isa<MDNode>(UTBAATag->getOperand(i+1)));

				Type *ElTy = cast<ValueAsMetadata>(UTBAATag->getOperand(i))->getType();
				MDNode *ElTBAATag = cast<MDNode>(UTBAATag->getOperand(i+1));
				Visited.insert(sTy);
				if (shouldProtectType(ElTy, Visited, ElTBAATag)) {
					StructTypesProtectInfo[key] = true;
					return true;
				}
			}
			
			StructTypesProtectInfo[key] = false;
			return false;
		} else {
			// This is not a union, go through all fields
			MDNode *STBAATag = StructsTBAA.lookup(sTy);

			const StructLayout *sl = DL->getStructLayout(sTy);
			size_t STBAAIndex = 0;

			for (unsigned i = 0, e = sTy->getNumElements(); i != e; ++i) {
				Type *eTy = sTy->getElementType(i);
				MDNode *ElTBAATag =
					getNextElTBAATag(STBAAIndex, eTy, sl, i, STBAATag);
				
				Visited.insert(sTy);
				if (shouldProtectType(eTy, Visited, ElTBAATag)) {
					// Cache the results to speedup future queries
					StructTypesProtectInfo[key] = true;
					return true;
				}
			}
			
			StructTypesProtectInfo[key] = false;
			return false;
		}
	}
	
	StructTypesProtectInfo[key] = false;
	return false;
}

// directly collect sensitive types
void CPSensitivePass::collectSensitiveTypes(Module &M) {
	// collect sensitive types from globals
	for (auto const &gV : M.globals()) {
		Type* eT = gV.getType();
		std::unordered_set<Type*> Visited;
		shouldProtectType(eT, Visited);
	}
	
	// collect sensitive types from instruction operands
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
		Function &f = *it;
		if (f.isDeclaration() || f.isIntrinsic()) {
			continue;
		}
		
		for (inst_iterator ii = inst_begin(f), ie = inst_end(f);
				ii != ie; ++ii) {
			Instruction* inst = &(*ii);
			std::unordered_set<Type*> Visited;
			shouldProtectType(inst->getType(), Visited);
			unsigned n = inst->getNumOperands();
			for (unsigned i = 0; i < n; ++i) {
				Value *operand = inst->getOperand(i);
				std::unordered_set<Type*> Visited;
				shouldProtectType(operand->getType(), Visited, inst->getMetadata(LLVMContext::MD_tbaa));
			}
		}
	}
}

void CPSensitivePass::dumpAllProtectedTypes() {
	errs() << "dumpAllProtectedTypes: \n";
	unordered_set<Type*> protectedStructTypes;
	for (auto it : StructTypesProtectInfo) {
		if (it.getSecond()) {
			protectedStructTypes.insert(it.getFirst());
			it.getFirst()->dump();
		}
	}
	errs() << "Totally, we got " << protectedStructTypes.size() << " types to protect!\n";
}

bool CPSensitivePass::handleCallsite(ImmutableCallSite CS, Function *F) {
	bool ret = false;
	Function::const_arg_iterator fItr = F->arg_begin();
	ImmutableCallSite::arg_iterator aItr = CS.arg_begin();
	
	// ignore functions that are too annoying
	const char *fn = F->getName().data();
	for (unsigned i = 0; IgnoreFuncs[i] != nullptr; ++i) {
		if (strcmp(IgnoreFuncs[i], fn) == 0) {
			return false;
		}
	}

	// do simple taint propagate
	for (unsigned i = 0; PropagateArgFuncs[i] != nullptr; i++) {
		unsigned fnLen = strlen(PropagateArgFuncs[i]);
		if (strncmp(PropagateArgFuncs[i], fn, fnLen) == 0) {
			Value *first = *aItr++;
			Value *second = *aItr;
			ret = addIfOneIsSensitive(first, second);
			return ret;
		}
	}
	
	if (F->isIntrinsic())
		return false;
	
	while (fItr != F->arg_end() && aItr != CS.arg_end()) {
		Argument *formal = const_cast<Argument*> (&(*fItr));
		Value *actual = *aItr;
		
		ret |= addIfOneIsSensitive(formal, actual);

		++fItr;
		++aItr;
	}

	while (aItr != CS.arg_end()) {
		Value *actual = *aItr;
		if (isValueSensitive(actual)) {
			SensitiveVarargMap[F] = true;
		}
		++aItr;
	}

	return ret;
}

bool CPSensitivePass::doTBAAOnFunction(llvm::Function &F) {
	bool ret = false;
	for (inst_iterator ii = inst_begin(F), ie = inst_end(F);
			ii != ie; ++ii) {
		Instruction* inst = &(*ii);
		/*	
		if (PtrToIntInst *ptiInst = dyn_cast<PtrToIntInst>(inst)) {
			if (!isValueSensitive(inst)) {
				AllSensitiveValues.insert(inst);
				ret |= true;	
			}
			if (!isValueSensitive(inst->getOperand(0))) {
				AllSensitiveValues.insert(inst->getOperand(0));
				ret |= true;
			}
		} else if (IntToPtrInst *itpInst = dyn_cast<IntToPtrInst>(inst)) {
			if (!isValueSensitive(inst)) {
				AllSensitiveValues.insert(inst);
				ret |= true;	
			}
			if (!isValueSensitive(inst->getOperand(0))) {
				AllSensitiveValues.insert(inst->getOperand(0));
				ret |= true;
			}
		} else */if (BitCastInst *bcInst = dyn_cast<BitCastInst>(inst)) {
			ret |= addIfOneIsSensitive(bcInst, bcInst->getOperand(0));
		} else if (LoadInst *lInst = dyn_cast<LoadInst>(inst)) {
			ret |= addSecondIfFirstIsSensitive(lInst, lInst->getPointerOperand());
		} else if (StoreInst *sInst = dyn_cast<StoreInst>(inst)) {
			bool tmpR = addSecondIfFirstIsSensitive(sInst->getValueOperand(), sInst->getPointerOperand());
			ret |= tmpR;
			if (isValueSensitive(sInst->getValueOperand()) || isValueSensitive(sInst->getPointerOperand()))
				ret |= addToSensitive(sInst);
		} else if (GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(inst)) {
			ret |= addSecondIfFirstIsSensitive(gepInst, gepInst->getPointerOperand());
			Value *pOperand = gepInst->getPointerOperand();
			Type *OTy = pOperand->getType();
			if (OTy->isVectorTy())
				OTy = OTy->getVectorElementType();
			Type *pTy = (cast<PointerType>(OTy))->getElementType();
			if (StructType *sTy = dyn_cast<StructType>(pTy)) {
				// if load from 'vararg' and it's sensitive, only i8* matters
				if (sTy->hasName() && sTy->getName() == "struct.__va_list_tag" && SensitiveVarargMap[&F]) {
					if (gepInst->getType()->isPointerTy()) {
						PointerType *pTy = cast<PointerType>(gepInst->getType());
						if (pTy->getElementType()->isIntegerTy(8)) {
							ret = addToSensitive(gepInst);
						}
					}
				}
			}
		} else if (CallInst *cInst = dyn_cast<CallInst>(inst)) {
			Function *f = cInst->getCalledFunction();
			ImmutableCallSite cs(cInst);
			if (f) {
				ret |= handleCallsite(cs, f);
				ret |= addValueIfReturnIsSensitive(inst, f);
				// add the return value if the current call is sensitive
				/*
				if (Func2RetValueMap.find(f) != Func2RetValueMap.end()) {
					ret |= addSecondIfFirstIsSensitive(cInst, Func2RetValueMap[f]);
				}
				*/
			} else {
				std::unordered_set<Function*> &targets = AllIndirectCalls[cInst->getCalledValue()];
				for (Function *target : targets) {
					ret |= handleCallsite(cs, target);
					ret |= addValueIfReturnIsSensitive(inst, target);
					// add the return value if the current call is sensitive
					/*
					if (Func2RetValueMap.find(target) != Func2RetValueMap.end()) {
						ret |= addSecondIfFirstIsSensitive(cInst, Func2RetValueMap[target]);
					}
					*/
				}
			}
		} else if (InvokeInst *iInst = dyn_cast<InvokeInst>(inst)) {
			Function *f = iInst->getCalledFunction();
			ImmutableCallSite cs(iInst);
			if (f) {
				ret |= handleCallsite(cs, f);
				ret |= addValueIfReturnIsSensitive(inst, f);
				// add the return value if the current invoke is sensitive
				/*
				if (Func2RetValueMap.find(f) != Func2RetValueMap.end()) {
					ret |= addSecondIfFirstIsSensitive(iInst, Func2RetValueMap[f]);
				}
				*/
			} else {
				std::unordered_set<Function*> &targets = AllIndirectCalls[iInst->getCalledValue()];
				for (Function *target : targets) {
					ret |= handleCallsite(cs, target);
					ret |= addValueIfReturnIsSensitive(inst, target);
					// add the return value if the current invoke is sensitive
					/*
					if (Func2RetValueMap.find(target) != Func2RetValueMap.end()) {
						ret |= addSecondIfFirstIsSensitive(iInst, Func2RetValueMap[target]);
					}
					*/
				}
			}
		} else if (ReturnInst *rInst = dyn_cast<ReturnInst>(inst)) {
			Value *retValue = rInst->getReturnValue();
			if (retValue && isValueSensitive(retValue)) {
				Function * f = inst->getParent()->getParent();
				SensitiveReturnMap[f] = true;
				if (Func2RetValueMap.find(f) != Func2RetValueMap.end())
					for (auto value : Func2RetValueMap[f])
						ret |= addToSensitive(value);
				ret |= addToSensitive(rInst);
			}
		} else if (PHINode *pNode = dyn_cast<PHINode>(inst)) {
			for (unsigned i = 0; i < pNode->getNumIncomingValues(); ++i) {
				Value *incomingV = pNode->getIncomingValue(i);
				ret |= addSecondIfFirstIsSensitive(incomingV, pNode);
			}
			for (unsigned i = 0; i < pNode->getNumIncomingValues(); ++i) {
				Value *incomingV = pNode->getIncomingValue(i);
				ret |= addSecondIfFirstIsSensitive(pNode, incomingV);
			}
		} else if (SelectInst *SI = dyn_cast<SelectInst>(inst)) {
			Value * TrueValue = SI->getTrueValue();
			Value * FalseValue = SI->getFalseValue();
			ret |= addSecondIfFirstIsSensitive(SI, TrueValue);
			ret |= addSecondIfFirstIsSensitive(SI, FalseValue); 
		} else if (ExtractElementInst *EEI = dyn_cast<ExtractElementInst>(inst)) {
			Value *vectorOperand = EEI->getVectorOperand();
			ret |= addSecondIfFirstIsSensitive(EEI, vectorOperand);
		} else if (ExtractValueInst *EVI = dyn_cast<ExtractValueInst>(inst)) {
			Value *aggregateOperand = EVI->getAggregateOperand();
			ret |= addSecondIfFirstIsSensitive(EVI, aggregateOperand);
		} else if (InsertElementInst *IEI = dyn_cast<InsertElementInst>(inst)) {
			Value *vectorOperand = IEI->getOperand(0);
			Value *valueOperand = IEI->getOperand(1);
			ret |= addSecondIfFirstIsSensitive(valueOperand, vectorOperand);
			ret |= addSecondIfFirstIsSensitive(valueOperand, IEI);
		} else if (InsertValueInst *IVI = dyn_cast<InsertValueInst>(inst)) {
			Value *baseOperand = IVI->getOperand(0);
			Value *valueOperand = IVI->getOperand(1);
			ret |= addSecondIfFirstIsSensitive(valueOperand, baseOperand);
			ret |= addSecondIfFirstIsSensitive(valueOperand, IVI);
		}
	}
	return ret;
}

// insert call into "ptwrite", with the (&ptwrite_chunk + value) as input
bool CPSensitivePass::insertPTWrite(Module &M, Value * value, BasicBlock::iterator insertPoint)
{
	LLVMContext & context = M.getContext();
	IntegerType * Int64Ty = Type::getInt64Ty(context);
	ConstantInt * Low22BitsMask = ConstantInt::get(Int64Ty, 0x3fffff);
	
	MDNode *node = MDNode::get(context, MDString::get(context, "ptwrite"));
	// instrument the call to "void ptwrite()"
	FunctionType * ptwriteFuncType = FunctionType::get(Type::getVoidTy(context), Int64Ty, (Type *)0);
	FunctionType * ptwriteChunkFuncType = FunctionType::get(Type::getVoidTy(context), (Type *)0);
	Constant * ptwriteChunk = M.getOrInsertFunction("ptwrite_chunk", ptwriteChunkFuncType);
	Constant * ptwriteConst = M.getOrInsertFunction("ptwrite", ptwriteFuncType);
	Function * ptwriteFunc = cast<Function>(ptwriteConst);
	ptwriteFunc->setCallingConv(CallingConv::C);
	Builder->SetInsertPoint(insertPoint);
	Value * fptrIntOld = Builder->CreatePtrToInt(ptwriteChunk, Int64Ty);
	Value * addend = Builder->CreateZExtOrTrunc(value, Int64Ty);

	// the last 22 bits
	Value * last12Bits = Builder->CreateAnd(addend, Low22BitsMask);
	Value * fptrIntNew = Builder->CreateAdd(fptrIntOld, last12Bits);
	Value * firstCall = Builder->CreateCall(ptwriteFunc, {fptrIntNew});
	(cast<Instruction>(firstCall))->setMetadata("ptwrite", node);
	(cast<Instruction>(firstCall))->setMetadata("ptwrite-bbid", node);

	return true;
}

// insert call into "ptwrite", with the (&ptwrite_chunk + value + 4K) as input
// the goal is to afford negative value, like (-10), by changing it to positive
bool CPSensitivePass::insertPTWriteAdd4K(Module &M, Value * value, BasicBlock::iterator insertPoint)
{
	LLVMContext & context = M.getContext();
	IntegerType * Int64Ty = Type::getInt64Ty(context);
	ConstantInt * Low22BitsMask = ConstantInt::get(Int64Ty, 0x3fffff);
	ConstantInt * Constant4K = ConstantInt::get(Int64Ty, 0x1000);
	
	MDNode *node = MDNode::get(context, MDString::get(context, "ptwrite"));
	// instrument the call to "void ptwrite()"
	FunctionType * ptwriteFuncType = FunctionType::get(Type::getVoidTy(context), Int64Ty, (Type *)0);
	FunctionType * ptwriteChunkFuncType = FunctionType::get(Type::getVoidTy(context), (Type *)0);
	Constant * ptwriteChunk = M.getOrInsertFunction("ptwrite_chunk", ptwriteChunkFuncType);
	Constant * ptwriteConst = M.getOrInsertFunction("ptwrite", ptwriteFuncType);
	Function * ptwriteFunc = cast<Function>(ptwriteConst);
	ptwriteFunc->setCallingConv(CallingConv::C);
	Builder->SetInsertPoint(insertPoint);
	Value * fptrIntOld = Builder->CreatePtrToInt(ptwriteChunk, Int64Ty);
	Value * addend = Builder->CreateZExtOrTrunc(value, Int64Ty);
	addend = Builder->CreateAdd(addend, Constant4K);

	// the last 12 bits
	Value * last12Bits = Builder->CreateAnd(addend, Low22BitsMask);
	Value * fptrIntNew = Builder->CreateAdd(fptrIntOld, last12Bits);
	Value * firstCall = Builder->CreateCall(ptwriteFunc, {fptrIntNew});
	(cast<Instruction>(firstCall))->setMetadata("ptwrite", node);
	(cast<Instruction>(firstCall))->setMetadata("ptwrite-cdata", node);

	return true;
}

// instrument one BasicBlock to dump its ID to PT trace
bool CPSensitivePass::insertPTWriteCallToBB(Module &M, BasicBlock * BB)
{
	auto iter = allInstrumentedBBs.find(BB);
	if (iter != allInstrumentedBBs.end())
		return false;

	allInstrumentedBBs.emplace(BB, BBID);
	LLVMContext & context = M.getContext();
	BasicBlock::iterator insertPoint = BB->getFirstInsertionPt();
	Constant * IDConstant = ConstantInt::get(Type::getInt64Ty(context), BBID++);
	insertPTWrite(M, IDConstant, insertPoint);

	return true;
}

void CPSensitivePass::replaceCEOWithInstr(Instruction * I, Value * pointer)
{
	if (ConstantExpr * CE = dyn_cast<ConstantExpr>(pointer))
	{
		switch (CE->getOpcode())
		{
			case Instruction::BitCast:
			case Instruction::GetElementPtr:
				{
					if (PHINode * PN = dyn_cast<PHINode>(I))
					{
						// special handling of the PHINode
						// 1. should insert the new instruction in the corresponding incoming BB
						// 2. should replace the incoming value with the new instruction ONE BY ONE
						//	otherwise, it is possible from some branches, the value is undefined.
						//
						//	see the following example:
						//
						//	bb0:
						//	  
						//	bb1:
						//	
						//	bb_last:
						//	  %ret = phi i8* [ (getelementptr %1, 0), bb0], [ (getelementptr %1, 0), bb1], ...
						//
						//
						//	if we create a new GEPI in bb0, and replace all uses with the new GEPI,
						//	the second use will also be replaced. But if the code comes from bb1, the
						//	GEPI is not defined then.
						Instruction * insertionPtr = nullptr;
						unsigned incomingValuesNum = PN->getNumIncomingValues();
						BasicBlock * BB = nullptr;
						for (unsigned index = 0; index < incomingValuesNum; index++) {
							Value * value = PN->getIncomingValue(index);
							if (value == pointer)
							{
								BB = PN->getIncomingBlock(index);

								insertionPtr = BB->getFirstInsertionPt();
								Instruction * newI = CE->getAsInstruction();
								newI->insertBefore(insertionPtr);
								PN->setIncomingValue(index, newI);

								for (unsigned index_2 = index + 1; index_2 < incomingValuesNum; index_2++)
									if (PN->getIncomingBlock(index_2) == BB)
										PN->setIncomingValue(index_2, newI);

								findConstantExpr(newI);
							}
						}
					} else {
						Instruction * insertionPtr = I->getParent()->getFirstInsertionPt();
						Instruction * newI = CE->getAsInstruction();
						newI->insertBefore(insertionPtr);
						I->replaceUsesOfWith(CE, newI);
						findConstantExpr(newI);
					}
					break;
				}
			default:
				break;
		}
	}
}

void CPSensitivePass::findConstantExpr(Instruction * I)
{
	unsigned operandNum = I->getNumOperands();
	for (unsigned index = 0; index < operandNum; index++)
	{
		Value * operand = I->getOperand(index);
		if (operand->getType()->isPointerTy() &&
			isa<ConstantExpr>(operand))
			replaceCEOWithInstr(I, operand);
	}
}

// this function is used to replace all constant expression inside an instruciton 
// with a complete instruction
void CPSensitivePass::ConstantExpr2Instruction(Module &M)
{
	for (auto &F : M)
		for (auto &BB : F)
			for (auto &I : BB)
				if (isa<LandingPadInst>(&I))
					// TODO: handle this
					continue;
				else
					findConstantExpr(&I);
}

void CPSensitivePass::SensitiveFuncAnalysis(Module * M)
{
	SensitiveFuncs.clear();

	// if one function contained >= 1 sensitive instruction,
	// it is sure a sensitive function
	for (Module::iterator it = M->begin(), ie = M->end(); 
			it != ie; ++it) {
		Function &f = *it;
		if (f.isDeclaration() || f.isIntrinsic())
			continue;
		for (inst_iterator ii = inst_begin(f), ie = inst_end(f);
				ii != ie; ++ii) {
			Instruction *inst = &(*ii);
			if (isValueSensitive(inst)) {
				if (functionNoRet.find(&f) == functionNoRet.end()) {
					SensitiveFuncs.insert(&f);
					//errs() << "sensitive func based on rule 1: " << f.getName() << "\n";
					//inst->dump();
					break;
				}
			}
		}
	}

	bool findNew = true;
	while (findNew) {
		findNew = false;
		for (Module::iterator it = M->begin(), ie = M->end(); 
				it != ie; ++it) {
			Function &f = *it;
			if (f.isDeclaration() || f.isIntrinsic())
				continue;
			if (SensitiveFuncs.find(&f) != SensitiveFuncs.end())
				continue;
			for (inst_iterator ii = inst_begin(f), ie = inst_end(f);
					ii != ie; ++ii) {
				Instruction *inst = &(*ii);
				if (isa<CallInst>(inst) || isa<InvokeInst>(inst)) {
					CallSite CS(inst);
					if (CallInst * CI = dyn_cast<CallInst>(inst))
						if (CI->isInlineAsm())
							continue;
					if (!CS.getCalledFunction()) {
						SensitiveFuncs.insert(&f);
						//errs() << "sensitive func based on rule 2: " << f.getName() << "\n";
						//inst->dump();
						findNew = true;
						break;
					} else {
						Function * F = CS.getCalledFunction();
						if (SensitiveFuncs.find(F) != SensitiveFuncs.end()) {
							if (functionNoRet.find(&f) == functionNoRet.end()) {
								SensitiveFuncs.insert(&f);
								//errs() << "sensitive func based on rule 3: " << f.getName() << "\n";
								//inst->dump();
								findNew = true;
								break;
							}
						}
					}
				}
			}
		}
	}

}

// add sensitive call instructions in
void CPSensitivePass::addSensitiveCallIn(Module &M)
{
	LLVMContext &ctx = M.getContext();

	// find all functions that have no return instruction
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) 
	{
		Function &F = *it;
		if (F.isDeclaration() || F.isIntrinsic())
			continue;

		bool doReturn = false;
		for (inst_iterator ii = inst_begin(F), ie = inst_end(F);
				ii != ie; ++ii) 
		{
			Instruction * I = &(*ii);
			if (ReturnInst * RI = dyn_cast<ReturnInst>(I))
				doReturn = true;
		}
		if (!doReturn) {
			errs() << "no return function: " << F.getName() << "\n";
			//functionNoRet.insert(&F);
		}
	}

	// 1) add indirect function call instructions in (except inlinAsm)
	// 2) add direct call to intrinsics with sensitive args in
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it)  {
		Function &F = *it;

		if (F.isDeclaration() || F.isIntrinsic())
			continue;

		for (inst_iterator ii = inst_begin(F), ie = inst_end(F); ii != ie; ++ii) {
			Instruction * I = &(*ii);

			if (!isa<CallInst>(I) && !isa<InvokeInst>(I))
				continue;

			CallSite * CS = new CallSite(I);
			Function * Func = CS->getCalledFunction();
			Value * calledValue = CS->getCalledValue();

			if (!Func) {
				if (!isa<InlineAsm>(calledValue)) {
					if (addToSensitive(I)) {
						MDNode *node = MDNode::get(ctx, MDString::get(ctx, "yes"));
						I->setMetadata("is-less-sensitive", node);
					}
				}
			} else {
				// do not care about direct function calls 
				// except calling into these functions
				if (Func->isIntrinsic() && (Func->getName() == "llvm.memcpy.p0i8.p0i8.i64" ||
											Func->getName() == "llvm.memmove.p0i8.p0i8.i64" ||
											Func->getName() == "llvm.va_start" ||
											Func->getName() == "llvm.va_end") ) {
					unsigned num_args = CS->arg_size();
					for (unsigned index = 0; index < num_args; index++) {
						Value * Arg = CS->getArgument(index);
						if (isValueSensitive(Arg)) {
							if (addToSensitive(I)) {
								MDNode *node = MDNode::get(ctx, MDString::get(ctx, "yes"));
								I->setMetadata("is-less-sensitive", node);
							}
							break;
						}
					}
				}
			}
		}
	}

	// find sensitive functions 
	SensitiveFuncAnalysis(&M);
	for (auto F : functionNoRet)
		SensitiveFuncs.erase(F);

	// add the instructions calling to sensitive functions
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) 
	{
		Function &F = *it;
		if (F.isDeclaration() || F.isIntrinsic())
			continue;

		for (inst_iterator ii = inst_begin(F), ie = inst_end(F);
				ii != ie; ++ii) 
		{
			Instruction *inst = &(*ii);
			if (isa<CallInst>(inst) || isa<InvokeInst>(inst)) {
				CallSite CS(inst);
				Function * F = CS.getCalledFunction();
				if (F && SensitiveFuncs.find(F) != SensitiveFuncs.end()) {
					if (addToSensitive(inst)) {
						MDNode *node = MDNode::get(ctx, MDString::get(ctx, "yes"));
						inst->setMetadata("is-less-sensitive", node);
					}
				}
			}
		}
	}
}

// this function achieves two tasks
// 
// 1) instrument GEPI & Select to dump index/condition
// 2) instrument Basic Block to dump BBID
//
void CPSensitivePass::doInstrumentation(Module &M)
{
	errs() << "Instrumenting sensitive instructions...\n";

	for (auto value : AllSensitiveValues) {
		Instruction * I = dyn_cast<Instruction>(value);

		if (!I || I->getParent()->getParent()->hasAvailableExternallyLinkage())
			continue;

		if (isa<UnreachableInst>(I) || 
				isa<BranchInst>(I) ||
				isa<SwitchInst>(I) || 
				isa<ResumeInst>(I) ||
				isa<BitCastInst>(I))
			continue;

		if (GetElementPtrInst * GEPI = dyn_cast<GetElementPtrInst>(I)) {
			BasicBlock::iterator insertPoint(I);
			unsigned idx_num = GEPI->getNumIndices();
			for (unsigned idx = 0; idx < idx_num; idx++) {
				Value * Index = GEPI->getOperand(idx + 1);
				if (!isa<ConstantInt>(Index) && !isa<ConstantDataVector>(Index))
					insertPTWriteAdd4K(M, Index, insertPoint);
			}
		} else if (SelectInst * SI = dyn_cast<SelectInst>(I)) {
			BasicBlock::iterator insertPoint(I);
			insertPTWriteAdd4K(M, SI->getCondition(), insertPoint);
		} else if (PHINode * PN = dyn_cast<PHINode>(I)) {
			if (!PN->hasConstantValue())
				allInstrumentedPHINodes.emplace(cast<PHINode>(I));
		}

		//insert the function call before this basicblock
		insertPTWriteCallToBB(M, I->getParent());
	}

	// for each instrumented PHINode, instrument all its incoming BBs
	for (auto & PN : allInstrumentedPHINodes) {
		unsigned incomingNum = PN->getNumIncomingValues();
		for (unsigned index = 0; index < incomingNum; index++) {
			BasicBlock * incomingBB = PN->getIncomingBlock(index);
			if (allInstrumentedBBs.find(incomingBB) == allInstrumentedBBs.end()) {
				insertPTWriteCallToBB(M, incomingBB);
			}
		}
	}

	errs() << "END: Applying uCFI for " << M.getModuleIdentifier() << '\n';

	saveModule(M, M.getName());
}

// this function is to shift all indirect function call into 
// the special function "indirect_call_*" --- so that we can use
// filter to only track a small region
void CPSensitivePass::doShiftIndirectCall(Module &M) 
{
	LLVMContext & context = M.getContext();
	FunctionType * argFuncType = FunctionType::get(Type::getVoidTy(context), (Type *)0);
	PointerType * argFuncPointerType = argFuncType->getPointerTo();
	std::vector<Type *> ParamsType;

	// we have not seen any function returing a structure
	bool firstStruct = true;
	Type * previousStructTy = nullptr;

	// return non-floating point type
	FunctionType * ICFuncType = FunctionType::get(Type::getInt64Ty(context), 
			ParamsType, true);
	Constant * ICFuncConstant = M.getOrInsertFunction("indirect_call", ICFuncType);
	Function * ICFunc = cast<Function>(ICFuncConstant);
	ICFunc->setCallingConv(CallingConv::C);

	// return float
	FunctionType * ICFloatFuncType = FunctionType::get(Type::getFloatTy(context), 
			ParamsType, true);
	Constant * ICFloatFuncConstant = M.getOrInsertFunction("indirect_call_float", 
			ICFloatFuncType);
	Function * ICFloatFunc = cast<Function>(ICFloatFuncConstant);
	ICFloatFunc->setCallingConv(CallingConv::C);

	// return double
	FunctionType * ICDoubleFuncType = FunctionType::get(Type::getDoubleTy(context), 
			ParamsType, true);
	Constant * ICDoubleFuncConstant = M.getOrInsertFunction("indirect_call_double", 
			ICDoubleFuncType);
	Function * ICDoubleFunc = cast<Function>(ICDoubleFuncConstant);
	ICDoubleFunc->setCallingConv(CallingConv::C);

	// return long double
	FunctionType * ICLDoubleFuncType = FunctionType::get(Type::getX86_FP80Ty(context),
			ParamsType, true);
	Constant * ICLDoubleFuncConstant = M.getOrInsertFunction("indirect_call_ldouble", 
			ICLDoubleFuncType);
	Function * ICLDoubleFunc = cast<Function>(ICLDoubleFuncConstant);
	ICLDoubleFunc->setCallingConv(CallingConv::C);

	GlobalVariable * TargetFunc = new GlobalVariable(M,
			argFuncPointerType, false, GlobalValue::ExternalLinkage,
			nullptr, "ICTarget");

	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
		Function &F = *it;
		if (F.isDeclaration() || F.isIntrinsic())
			continue;

		for (inst_iterator ii = inst_begin(F), ie = inst_end(F);
				ii != ie;) 
		{
			Instruction * I = &(*ii++);
			if (CallInst * CI = dyn_cast<CallInst>(I)) {
				if (CI->getCalledFunction() != nullptr)
					continue;
				if (CI->getMetadata("ptwrite"))
					continue;
				if (CI->isInlineAsm())
					continue;

				Builder->SetInsertPoint(I);
				Value * calledValue = CI->getCalledValue();
				Value * funcPointer = Builder->CreateBitCast(calledValue, argFuncPointerType);
				std::vector<Value *> Params;
				Params.insert(Params.begin(), CI->arg_operands().begin(),
						CI->arg_operands().end());
				Builder->CreateStore(funcPointer, TargetFunc);
				
				Value * newCall = nullptr;
				Value * newRet = nullptr;
				Type * originalType= CI->getType();
				if (originalType->isStructTy() && (firstStruct || originalType == previousStructTy)) {
					// return structure
					firstStruct = false;
					previousStructTy = originalType;

					FunctionType * ICStructFuncType = FunctionType::get(originalType, ParamsType, true);
					Constant * ICStructFuncConstant = M.getOrInsertFunction("indirect_call_struct",
							ICStructFuncType);
					Function * ICStructFunc = cast<Function>(ICStructFuncConstant);
					ICStructFunc->setCallingConv(CallingConv::C);

					newCall = Builder->CreateCall(ICFunc, Params);
					newRet = newCall;
				} else if (!originalType->isFloatingPointTy()) {
					newCall = Builder->CreateCall(ICFunc, Params);
					newRet = nullptr;
					if (originalType->isPointerTy()) 
						newRet = Builder->CreateIntToPtr(newCall, originalType);
					else if (originalType->isIntegerTy())
						newRet = Builder->CreateZExtOrTrunc(newCall, originalType);
					else if (originalType->isVoidTy()) {
						newRet = newCall;
					} else {
							errs() << "need to write a cast here for type: " << *originalType << "\n";
							CI->dump();
					}
				} else if (originalType->isFloatTy()) {
					newCall = Builder->CreateCall(ICFloatFunc, Params);
					newRet = newCall;
				} else if (originalType->isDoubleTy()) {
					newCall = Builder->CreateCall(ICDoubleFunc, Params);
					newRet = newCall;
				} else if (originalType->isX86_FP80Ty()) {
					newCall = Builder->CreateCall(ICLDoubleFunc, Params);
					newRet = newCall;
				} else 
					errs() << "types not handled: " << *originalType << "\n";

				SmallVector<Instruction *, 16> callUsers;
				for (auto user : CI->users())
					callUsers.push_back(dyn_cast<Instruction>(user));
				for (auto user : callUsers)
					user->replaceUsesOfWith(CI, newRet);

				CI->eraseFromParent();
			} else if (InvokeInst * II = dyn_cast<InvokeInst>(I)) {
				if (II->getCalledFunction() != nullptr)
					continue;
				if (II->getMetadata("ptwrite"))
					continue;

				Builder->SetInsertPoint(I);
				Value * calledValue = II->getCalledValue();
				Value * funcPointer = Builder->CreateBitCast(calledValue, argFuncPointerType);
				std::vector<Value *> Params;
				Params.insert(Params.begin(), II->arg_operands().begin(),
						II->arg_operands().end());
				Builder->CreateStore(funcPointer, TargetFunc);

				BasicBlock * curBB = I->getParent();

				Value * newCall = nullptr;
				Value * newRet = nullptr;
				Type * originalType= II->getType();
				
				if (originalType->isStructTy() && (firstStruct || originalType == previousStructTy)) {
					// return structure
					firstStruct = false;
					previousStructTy = originalType;

					FunctionType * ICStructFuncType = FunctionType::get(originalType, ParamsType, true);
					Constant * ICStructFuncConstant = M.getOrInsertFunction("indirect_call_struct",
							ICStructFuncType);
					Function * ICStructFunc = cast<Function>(ICStructFuncConstant);
					ICStructFunc->setCallingConv(CallingConv::C);

					newCall = Builder->CreateInvoke(ICStructFunc, II->getNormalDest(), II->getUnwindDest(), Params);
					newRet = newCall;
				} else if (!originalType->isFloatingPointTy()) {
					//if (!originalType->isIntegerTy(1))
					//	continue;

					newCall = Builder->CreateInvoke(ICFunc, II->getNormalDest(), II->getUnwindDest(), Params);

					if (originalType->isPointerTy()) {
						newRet = Builder->CreateIntToPtr(newCall, originalType);

						Instruction * newRetI = cast<Instruction>(newRet);
						InvokeInst * newCallI = cast<InvokeInst>(newCall);
						BasicBlock * oldNormalBB = newCallI->getNormalDest();
						BasicBlock * UnwindBB = newCallI->getUnwindDest();
						BasicBlock * newBB = SplitBlock(curBB, newRetI, this);
						newCallI->setNormalDest(newBB);
						II->setNormalDest(newBB);
						curBB->getTerminator()->eraseFromParent();
						BasicBlock::iterator iter = newRetI;
						iter++;
						Builder->SetInsertPoint(iter);
						Builder->CreateBr(oldNormalBB);

						for (BasicBlock::iterator ii = UnwindBB->begin(), iiEnd = UnwindBB->end();
								ii != iiEnd; ii++) {
							if (PHINode * PN = dyn_cast_or_null<PHINode>(ii)) {
								unsigned incomingNum = PN->getNumIncomingValues();
								for (unsigned index = 0; index < incomingNum; index++) {
									BasicBlock * BB = PN->getIncomingBlock(index);
									if (BB == newBB) {
										PN->setIncomingBlock(index, curBB);
										break;
									}
								}
							} else
								break;
						}

					} else if (originalType->isIntegerTy() && !originalType->isIntegerTy(64)) {
						newRet = Builder->CreateSExtOrTrunc(newCall, originalType);
						
						Instruction * newRetI = cast<Instruction>(newRet);
						InvokeInst * newCallI = cast<InvokeInst>(newCall);
						BasicBlock * oldNormalBB = newCallI->getNormalDest();
						BasicBlock * UnwindBB = newCallI->getUnwindDest();

						BasicBlock * newBB = SplitBlock(curBB, newRetI, this);
						newCallI->setNormalDest(newBB);
						II->setNormalDest(newBB);

						curBB->getTerminator()->eraseFromParent();

						BasicBlock::iterator iter = newRetI;
						iter++;
						Builder->SetInsertPoint(iter);
						Builder->CreateBr(oldNormalBB);

						for (BasicBlock::iterator ii = UnwindBB->begin(), iiEnd = UnwindBB->end();
								ii != iiEnd; ii++) {
							if (PHINode * PN = dyn_cast_or_null<PHINode>(ii)) {
								unsigned incomingNum = PN->getNumIncomingValues();
								for (unsigned index = 0; index < incomingNum; index++) {
									BasicBlock * BB = PN->getIncomingBlock(index);
									if (BB == newBB) {
										PN->setIncomingBlock(index, curBB);
										break;
									}
								}
							} else
								break;
						}

					} else if (originalType->isIntegerTy(64) || originalType->isVoidTy()) {
						newRet = newCall;
					} else {
						errs() << "need to write a cast here for type: " << *originalType << "\n";
						II->dump();
					}
				} else if (originalType->isFloatTy()) {
					newCall = Builder->CreateInvoke(ICFloatFunc, II->getNormalDest(), II->getUnwindDest(), Params);
					newRet = newCall;
				} else if (originalType->isDoubleTy()) {
					newCall = Builder->CreateInvoke(ICDoubleFunc, II->getNormalDest(), II->getUnwindDest(), Params);
					newRet = newCall;
				} else if (originalType->isX86_FP80Ty()) {
					newCall = Builder->CreateInvoke(ICLDoubleFunc, II->getNormalDest(), II->getUnwindDest(), Params);
					newRet = newCall;
				} else 
					errs() << "types not handled: " << *originalType << "\n";

				SmallVector<Instruction *, 16> callUsers;
				for (auto user : II->users())
					callUsers.push_back(dyn_cast<Instruction>(user));
				for (auto user : callUsers)
					user->replaceUsesOfWith(II, newRet);

				II->eraseFromParent();
			} 
		}
	}

	//saveModule(M, "hh");
}

bool CPSensitivePass::hasSensitiveUses(Instruction * I)
{
	bool ret = false;
	std::unordered_set<Instruction *> visited;
	_hasSensitiveUses(I, visited, ret);
	
	return ret;
}

void CPSensitivePass::_hasSensitiveUses(Instruction * I, std::unordered_set<Instruction *> &visited, bool &ret)
{
	auto iter = visited.find(I);
	if (iter != visited.end())
		return;

	visited.insert(I);

	if (isValueSensitive(I)) {
		if (isa<CallInst>(I) || isa<InvokeInst>(I) || 
			isa<StoreInst>(I) || isa<ReturnInst>(I)) {
			ret = true;
			return;
		}
	} else 
		return;

	for (auto user : I->users())
		if (Instruction * inst = dyn_cast<Instruction>(user)) {
			_hasSensitiveUses(inst, visited, ret);
			if (ret) return;
		}

	return;
}

bool CPSensitivePass::hasSensitiveInstrs(Function * func)
{
	bool ret = false;
	std::unordered_set<Function *> visited;
	_hasSensitiveInstrs(func, visited, ret);
	
	return ret;
}

void CPSensitivePass::_hasSensitiveInstrs(Function * func, std::unordered_set<Function *> &visited, bool &ret)
{
	auto iter = visited.find(func);
	if (iter != visited.end())
		return;

	visited.insert(func);

	std::unordered_set<Function *> calledFuncs;
	for (inst_iterator ii = inst_begin(func), ie = inst_end(func); ii != ie; ++ii) {
		Instruction * I = &(*ii);

		if (isValueSensitive(I)) {
			if (!isa<CallInst>(I) && !isa<InvokeInst>(I)) {
				ret = true;
				return;
			} else {
				CallSite * CS = new CallSite(I);
				Function * Func = CS->getCalledFunction();
				if (!Func) {
					ret = true;
					return;
				} else
					calledFuncs.insert(Func);
			}
		}
	}

	for (auto Func : calledFuncs) {
		_hasSensitiveInstrs(Func, visited, ret);
		if (ret) return;
	}

	return;
}

bool CPSensitivePass::pointToI8(Type * type) {
	if (type->isPointerTy()) {
		Type * pointedType = cast<PointerType>(type)->getElementType();
		if (pointedType->isIntegerTy(8))
			return true;
		else
			return pointToI8(pointedType);
	} else
		return false;
}

// revoke the sensitivity of some instructions
void CPSensitivePass::revokeSensitivity(Module & M)
{
	bool revoked = true;
	unsigned counter = 0;
	std::unordered_set<Value *> toBeRemoved;

	while (revoked) {
		revoked = false;
		toBeRemoved.clear();

		for (Value *sV : AllSensitiveValues) {
			if (Instruction *I = dyn_cast<Instruction>(sV)) {
				if (!hasSensitiveUses(I)) {
					if (!isa<CallInst>(I) && 
							!isa<InvokeInst>(I) &&
							!isa<StoreInst>(I) &&
							!isa<ReturnInst>(I)) {
						revoked = true;
						toBeRemoved.insert(sV);
					} else if (StoreInst * SI = dyn_cast<StoreInst>(I)) {
						Value * value = SI->getValueOperand();
						if (!isValueSensitive(value) && 
							!isTypeSensitive(value->getType())) {
							//errs() << "remove --- " << *SI << "\n";
							revoked = true;
							toBeRemoved.insert(sV);
						}
					}
				}
			}
		}

		for (Value *sV : toBeRemoved) {
			counter++;
			AllSensitiveValues.erase(sV);

			LLVMContext &ctx = M.getContext();
			MDNode *node = MDNode::get(ctx, MDString::get(ctx, "no"));
			cast<Instruction>(sV)->setMetadata("remove-sensitivity", node);
		}
	}

	errs() << "erase " << counter << " sensitive values\n";

	char * unused_comment = "revmoe functions without any sensitive instruction from the set";
	std::unordered_set<Function *> toBeRemovedFunc;
	for (auto F : SensitiveFuncs) {

		if (!hasSensitiveInstrs(F)) {
			errs() << "revoke sensitive function " << F->getName() << "\n";
			toBeRemovedFunc.insert(F);
		}
	}

	for (auto F: toBeRemovedFunc)
		SensitiveFuncs.erase(F);

	std::unordered_set<Instruction *> toBeRemovedCallInstrs;
	// revoke sensitive to call instructions to removed functions
	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) 
	{
		Function &F = *it;
		if (F.isDeclaration() || F.isIntrinsic())
			continue;

		for (inst_iterator ii = inst_begin(F), ie = inst_end(F);
				ii != ie; ++ii) 
		{
			Instruction * I = &(*ii);
			if (!isa<CallInst>(I) && !isa<InvokeInst>(I))
				continue;

			CallSite * CS = new CallSite(I);
			Function * Func = CS->getCalledFunction();
			if (Func) {
				auto iter = toBeRemovedFunc.find(Func);
				if (iter != toBeRemovedFunc.end())
					toBeRemovedCallInstrs.insert(I);
			}
		}
	}

	for (auto I : toBeRemovedCallInstrs)
		AllSensitiveValues.erase(I);

	if (toBeRemovedCallInstrs.size() != 0)
		revokeSensitivity(M);
}

bool CPSensitivePass::runOnModule(llvm::Module &M) {

	// Initialization

	// obtain analysis result
	DL = &getAnalysis<DataLayoutPass>().getDataLayout();
	TLI = &getAnalysis<TargetLibraryInfo>();
	AA = &getAnalysis<AliasAnalysis>();
	//initialize the IR Builder
	const DataLayout *DL = M.getDataLayout();
	BuilderTy TheBuilder(M.getContext(), TargetFolder(DL));
	Builder = &TheBuilder;
	// initialize
	BBID = 1;	// reserve 0 for un-instrumentation 
	allInstrumentedPHINodes.clear();
	allInstrumentedBBs.clear();

	ConstantExpr2Instruction(M);

	// get all tbaa nodes
	NamedMDNode *STBAA = M.getNamedMetadata("clang.tbaa.structs");
	if (!STBAA) {
		printf("TBAA: clang.tbaa.structs is null! Skip the ucfi pass\n");
		//return false;
	}
	for (size_t i = 0, e = STBAA->getNumOperands(); i != e; ++i) {
		MDNode *MD = STBAA->getOperand(i);
		MDNode *TBAATag = dyn_cast_or_null<MDNode>(MD->getOperand(1));
		ValueAsMetadata *ValMD = dyn_cast_or_null<ValueAsMetadata>(MD->getOperand(0));
		if (TBAATag && ValMD) {
			StructsTBAA[cast<StructType>(ValMD->getType())] = TBAATag;
		}
	}

	NamedMDNode *UTBAA = M.getNamedMetadata("clang.tbaa.unions");
	if (!UTBAA) {
		printf("TBAA: clang.tbaa.unions is null! Skip the ucfi pass\n");
		//return false;
	}
	for (size_t i = 0, e = UTBAA->getNumOperands(); i != e; ++i) {
		MDNode *MD = UTBAA->getOperand(i);
		MDNode *TBAATag = dyn_cast_or_null<MDNode>(MD->getOperand(1));
		ValueAsMetadata *ValMD = dyn_cast_or_null<ValueAsMetadata>(MD->getOperand(0));
		if (TBAATag && ValMD) {
			UnionsTBAA[cast<StructType>(ValMD->getType())] = TBAATag;
		}
	}

	analyzeIndirectCalls(M);
	collectSensitiveTypes(M);
	//dumpAllProtectedTypes();

	for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
		Function &f = *it;
		if (f.isDeclaration() || f.isIntrinsic())
			continue;

		for (inst_iterator ii = inst_begin(f), ie = inst_end(f);
				ii != ie; ++ii) {
			Instruction* inst = &(*ii);
			
			if (valueWithSensitiveType(inst) && inst->getNumUses() != 0)
				addToSensitive(inst);

			StoreInst *sInst = dyn_cast<StoreInst>(inst);

			for (unsigned i = 0, n = inst->getNumOperands(); i < n; ++i) {
				Value *operand = inst->getOperand(i);
				if (valueWithSensitiveType(operand)) {
					addToSensitive(operand);
					if (sInst) {
						addToSensitive(sInst);
					}
				}
			}

			// for store instruction, if the pointer value is bitcasted, we check
			//
			//    1) the original type is a pointer type (A) of anoter pointer type (B)
			//	  2) pointer type (B) is sensitive
			//
			// we will add the value to store into sensitive set
			if (StoreInst *SI = dyn_cast<StoreInst>(inst)) {
				Value * pointer = SI->getPointerOperand();
				Value * value   = SI->getValueOperand();

				if (BitCastInst * BCI = dyn_cast<BitCastInst>(pointer)) {
					if (value->getType()->isPointerTy()) {
						Type * srcType = BCI->getSrcTy();
						Type * pointedType = cast<PointerType>(srcType)->getElementType();

						if (pointedType->isPointerTy() && isTypeSensitive(pointedType)) {
							addToSensitive(value);
							addToSensitive(pointer);
						}
					}
				}
			/*
			// as for store instruction
			} else if (LoadInst * LI = dyn_cast<LoadInst>(inst)) {
				Value * pointer = LI->getPointerOperand();

				// mark sensitive
				LLVMContext &ctx = M.getContext();
				MDNode *node = MDNode::get(ctx, MDString::get(ctx, "yes"));

				if (!pointToI8(pointer->getType()))
					continue;

				if (BitCastInst * BCI = dyn_cast<BitCastInst>(pointer)) {
					Type * srcType = BCI->getSrcTy();
					if (srcType->isPointerTy()) {
						Type * pointedType = cast<PointerType>(srcType)->getElementType();

						if (pointedType->isPointerTy() && isTypeSensitive(pointedType)) {
							AllSensitiveValues.insert(LI);
							AllSensitiveValues.insert(BCI);
							LI->setMetadata("load-special", node);
							BCI->setMetadata("load-special", node);
				
						}
					}
				}
			*/
			} else if (ReturnInst *retInst = dyn_cast<ReturnInst>(inst)) {
				if (retInst->getNumOperands() > 0) {
					Func2RetValueMap[&f].push_back(retInst->getOperand(0));
				}
			}
		}
	}
	
	// until no values values are inserted into 'AllSensitiveValues'
	bool changed = true;
	while (changed) {
		changed = false;
		errs() << "got " << AllSensitiveValues.size() << " sensitive values\n";
		for (Module::iterator it = M.begin(), ie = M.end(); it != ie; ++it) {
			Function &f = *it;
			changed |= doTBAAOnFunction(f);
		}
	}

	addSensitiveCallIn(M);
	revokeSensitivity(M);

	// mark all identified instructions as sensitive
	LLVMContext &ctx = M.getContext();
	for (Value *sV : AllSensitiveValues) {
		if (Instruction *inst = dyn_cast<Instruction>(sV)) {
			MDNode *node = MDNode::get(ctx, MDString::get(ctx, "yes"));
			inst->setMetadata("is-sensitive", node);
		}
	}
	
	// set function attribute as "sensitive function"
	// and disable tail call optimization so as to keep ret instr
	for (auto F : SensitiveFuncs) {
		F->addFnAttr("sensitive-func");
		F->addFnAttr("disable-tail-calls", "true");
	}

	doInstrumentation(M);
	doShiftIndirectCall(M);
	
	return true;
}

char CPSensitivePass::ID = 0;
static RegisterPass<CPSensitivePass> X("CPSensitive", "uCFI instrumentation pass");

static void registerMyPass(const PassManagerBuilder &PMB,
		legacy::PassManagerBase &PM) {
	PM.add(new CPSensitivePass());
}

static RegisterStandardPasses RegisterMyPass(PassManagerBuilder::EP_OptimizerLast, registerMyPass);
static RegisterStandardPasses RegisterMyPass2(PassManagerBuilder::EP_EnabledOnOptLevel0, registerMyPass);
