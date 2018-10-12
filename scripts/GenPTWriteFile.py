#!/usr/bin/env python

import subprocess
import os
import sys

ss = False
if len(sys.argv) == 2 and sys.argv[1] == "ss":
    ss = True

file_name = "pt_write_sim.c"
if ss:
    print "for parallel shadow stack"
    file_name = "pt_write_sim_ss.c"
print "Generating the file " + file_name,

with open("pt_write_sim_base.c", "r") as in_file:
    with open(file_name, "w+") as out_file:
        if ss:
            out_file.write("#define PARALLEL_SHADOW_STACK\n")

        for line in in_file:
            if "PARALLEL_SS" in line:
                if ss:
                    out_file.write("\"add    $0x8,%rsp\\n\\t\"\n")
                    out_file.write("\"pushq  %ss:-0x7fffffff(%rsp)\\n\\t\"\n")
                else:
                    out_file.write("\"\"\n")
            elif "FILLRET" not in line:
                out_file.write(line)
            else:
                counter = 0;
                retNum = 1 << 22
                while counter < retNum:
                    counter += 1
                    out_file.write("\"ret\\n\\t\"\n")

print "file created, compiling..."
subprocess.call(["gcc", file_name, "-c", "-O3"])
print "Done"
