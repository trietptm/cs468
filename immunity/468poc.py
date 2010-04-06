#!/usr/bin/env python

"""
script that right now, hooks send/recv  but only really handles send stuff...
tabwidth = 4, spaces instead of tabs

put in C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands

run with !468poc at the bottom
"""

__VERSION__ = '0.000000001'

from immlib import *

DESC= "468 project poc"

class hooker(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = Debugger()
        imm.log("------------------------------")
        
        # Figure out which hook it is and print it
        func_name = imm.getKnowledge("%08x" % regs['EIP'])
        imm.log(func_name)
        
        if func_name == "ws2_32.send":
            # print_buffer returns the size of buffer... quick way to not
            # do call stacks of the 1 byte message
            if self.print_buffer(imm, func_name, regs) > 1:
                self.print_stack(imm, regs)
        elif func_name == "ws2_32.recv":
            self.print_buffer(imm, "ws2_32.send", regs)
    
    def print_buffer(self, imm, function, regs):
        if function == "ws2_32.send":
            # Get the pointer to the buffer
            buffer_ptr = imm.readMemory(regs['ESP'] + 8, 4)
            buffer_ptr = struct.unpack("L", buffer_ptr)[0]
            
            # Read buffer size
            size = imm.readMemory(regs['ESP'] + 12, 4)
            size = struct.unpack("i", size)[0]
            
            buffer = imm.readMemory(buffer_ptr, size)

            print_buff, hex_buff = self.get_printable_buffer(buffer, size)
            imm.log("    buffer pointer: %08x, size: %s." % (buffer_ptr, size))
            imm.log("    ascii: %s" % print_buff[:256])
            imm.log("    hex:   %s" % hex_buff[:128])
           
            # Something real quick to filter out the 1 byte messages
            return size
    
    def get_printable_buffer(self, buffer, length):
        counter = 0
        print_buff = ""
        hex_buff = ""
        while counter < length:
            if ord(buffer[counter]) >= 32 and ord(buffer[counter]) <= 126:
                print_buff += buffer[counter]
            else:
                print_buff += "."
            
            hex_buff += "0x%02x " % ord(buffer[counter])
            counter += 1
        
        return (print_buff, hex_buff)
            
    def print_stack(self, imm, regs):
        callstack = imm.callStack()
        for a in callstack:
            imm.log("Address: %08x - Stack: %08x - Procedure: %s - frame: %08x - called from: %08x" % \
                (a.address,a.stack,a.procedure,a.frame,a.calledfrom))
        
        
def main(args):
    imm = Debugger()
    target = imm.getDebuggedName()
    module = imm.getModule(target)

    if not module.isAnalysed():
        imm.analyseCode(module.getCodebase())
        
    hook = hooker()
    func_list = ["ws2_32.send", "ws2_32.recv"]
    for f in func_list:
        # Get fn address and add a hook there
        addr = imm.getAddress(f)
        hook.add(f, addr)
        
        # Store some info in immunity about the address's name for use later
        imm.addKnowledge("%08x" % addr, f)
        
        imm.log("Added hook for %s at %08x" % (f, addr))
        
    return "hooks set like a boss"
