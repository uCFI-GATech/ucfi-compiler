# uCFI-compiler

To use uCFI to harden your program, you also need [ucfi-kernel](https://github.com/uCFI-GATech/ucfi-kernel) and [ucfi-monitor](https://github.com/uCFI-GATech/ucfi-monitor).

## Introduction

uCFI-compiler compiles project source code into a hardened version, so that uCFI-monitor can protect its execution from control-flow hijacking attacks. See [the paper](https://gts3.org/assets/papers/2018/hu:ucfi.pdf) to find more details about the design, implementation and evalaution of uCFI. uCFI-compiler contains three components: LLVM pass, X86 backend and ptwrite emulator.

### 1. LLVM pass

The related code is in `llvm/lib/Transforms/NewCPSensitivePass`. The LLVM pass will complete the follows tasks:

* Identify constraining data and insert code to dump their value into PT trace at runtime

* Instrument each sensitive basic block (containing at least one control-instruction) to dump its unique ID

* Change function attribute to avoid tail call optimization

* Replace all indirect function call with a direct call to a specific function, where an indirect jump helps reach the real target

### 2. X86 backend

The related code is in `llvm/lib/Target/X86/X86AsmPrinter.cpp`. The X86 backend achieves two tasks

* Redirect each RET instruction to an dedicated RET instruction

* Provide a simple parallel shadow stack implementation proposed in [1].

   Note: uCFI adopts parallel shadow stack to demonstrate its compatibility with shadow stack solutions. We do not claim any contribution or guarantee on protecting the return address. All design novelties go to its orignal authors. This implementation is just a simple version written by uCFI authors. Any implementation bugs go to uCFI authors. Due to the implementation difference, overhead of parallel shadow stack could be different from that reported in the original paper.

### 3. ptwrite emulator

The related code is in `ptwrite-emulator`. ptwrite emulator helps dump arbitrary value (even non-control-flow data) into Intel PT trace. It mainly supports four features:

* A dedicated RET instrution to help achieve return for all functions

* A dedicated indirect JMP instruction to help achieve indirect function call

* A code region of all RET instructions to achieve the ptwrite emulation

* Help setup the parallel shadow stack

## Build Instructions

1. git pull this repo to local system

       git pull git@github.com:uCFI-GATech/ucfi-compiler.git && cd ucfi-compiler
    
2. create build and install folder

       mkdir {build,install} && cd build
    
3. configuration the compilation, compile and install 

       cmake -DCMAKE_INSTALL_PREFIX=../install -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 ../llvm/
       make -j 8
       make install
    
     Now you should have llvm & clang toolchains available in the `install` folder. run `source shrc` in the root directory to add the installation folder into `PATH`

4. build the ptwrite emulator

       #suppose you are under the root directory of this project
       cd ptwrite-emulator
       
       # if you want to use parallel shadow stack
       ./GenPTWriteFile.py ss
   
   You will get `pt_write_sim_ss.o` here, which is necessary to be linked into the final executable. Check [Compile a hello world to see how to use it](README.md#compile-a-hello-world).
   
       # if you do not want to use parallel shadow stack
       ./GenPTWriteFile.py
   
   You will get `pt_write_sim.o` here, which is necessary to be linked into the final executable.

## Compile a hello world

Currently, uCFI-compiler requires to work on one LLVM IR file of the whole project. In our work, we use [wllvm](https://github.com/travitch/whole-program-llvm) to generate the whole-program-LLVM-IR first, and then we use ucfi-compiler to generate the hardend executable and other auxiliary files. You can find how to use `wllvm` to generate the whole-program-LLVM-IR following [this link](https://github.com/travitch/whole-program-llvm). Of course, you can use other ways to generate this file, like through [llvm-link](http://llvm.org/docs/CommandGuide/llvm-link.html), or [linking-time-optimization](https://llvm.org/docs/LinkTimeOptimization.html). 

Suppose you have successfully get the one LLVM IR file, like `hello.bc` , here are the instructions to generate the hardened binary. 

1. Lower any indirect jump to if-else branch. Currently uCFI only handles indirect function calls. For indirect jump, we rely on the lowerswitch pass of opt to change them to if-else + direct jump. 

       opt -lowerswitch hello.bc -o hello.bc-A
       cp hello.bc-A hello.bc

2. If you do not want to use shadow stack

       clang++ -Xclang -load -Xclang $COMPILER_PATH/install/lib/LLVMCPSensitivePass.so -Xclang -add-plugin -Xclang -CPSensitive -mllvm -redirectRet $COMPILER_PATH/ptwrite-emulator/pt_write_sim.o hello.bc -o hardened-bin
    
3. If you want to use shadow stack

       clang++ -Xclang -load -Xclang $COMPILER_PATH/install/lib/LLVMCPSensitivePass.so -Xclang -add-plugin -Xclang -CPSensitive -mllvm -redirectRet $COMPILER_PATH/ptwrite-emulator/pt_write_sim_ss.o -mllvm -shadowstack hello.bc -o hardened-bin`
       
    
    At this stage, you should get the hardened binary, and the IR file named like `hello.bc_pt.bc`. You need both to run the monitor. 
    
4. Get the address-taken functions and code range to trace

       $MONITOR_PATH/scripts/GetFuncAddr.py hardened-bin > BB.info
       $MONITOR_PATH/scripts/RangeToTrace.py hardened-bin > filter-range
        
5. Notify the kernel about the program name and it trace range

       # disable ASLR
       echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
       
       ffrom=`cat filter-range | grep -io "0x[0-9A-F]*" | head -n 1`
       fto=`cat filter-range | grep -io "0x[0-9A-F]*" | tail -n 1`
       echo -n "$ffrom|$fto|hello" | sudo tee /sys/kernel/debug/pt_monitor
       
6. Let's run it
       
       # start the monitor
       sudo $MONITOR_PATH/build/KB3Main hello.bc.bc_pt.bc  BB.info /sys/kernel/debug/pt_output
       
       # start the program
       ./hello
       
       # check the log file pt_output-log.1 to see the results
       
7. clean up

       echo -e "\x00" | sudo tee /sys/kernel/debug/pt_monitor
    
## Paper

Hong Hu, Chenxiong Qian, Carter Yagemann, Simon Pak Ho Chung, William R. Harris, Taesoo Kim, and Wenke Lee. 2018. Enforcing Unique Code Target Property for Control-Flow Integrity. In Proceedings of the 2018 ACM SIGSAC Conference on Computer and Communications Security (CCS '18). ACM, New York, NY, USA, 1470-1486. DOI: https://doi.org/10.1145/3243734.3243797

```
@inproceedings{hu:ucfi,
  title        = {{Enforcing Unique Code Target Property for Control-Flow Integrity}},
  author       = {Hong Hu and Chenxiong Qian and Carter Yagemann and Simon Pak Ho Chung and William R. Harris and Taesoo Kim and Wenke Lee},
  booktitle    = {Proceedings of the 25th ACM Conference on Computer and Communications Security (CCS)},
  month        = oct,
  year         = 2018,
  address      = {Toronto, ON, Canada},
}
```

## Authors

[Hong Hu](https://www.cc.gatech.edu/~hhu86/)<br />
[Chenxiong Qian](https://0-14n.github.io/)<br />
[Carter Yaggemann](https://carteryagemann.com/)<br />
Simon Pak Ho Chung<br />
[William R. Harris](https://galois.com/team/bill-harris/)<br />
[Taesoo Kim](https://taesoo.kim/)<br />
[Wenke Lee](http://wenke.gtisc.gatech.edu/)

## Contacts (Gmail)

Hong Hu: huhong789<br />
Chenxiong Qian: chenxiongqian<br />
Carter Yagemann: carter.yagemann

## References

[1] Thurston H.Y. Dang, Petros Maniatis, and David Wagner. 2015. The Performance Cost of Shadow Stacks and Stack Canaries. In Proceedings of the 10th ACM Symposium on Information, Computer and Communications Security (ASIA CCS '15). ACM, New York, NY, USA, 555-566. DOI: https://doi.org/10.1145/2714576.2714635
