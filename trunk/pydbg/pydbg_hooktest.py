from pydbg import *
from pydbg.defines import *
import pefile
import sys
import signal
import math
import time
from optparse import OptionParser

#COMPLETELY ARBITRARY FOR NOW
ENTROPY_LIMIT = 0.80
EXE_ENTRY = None

def print_bps(dbg):
    print "BPS: "
    for bp in dbg.breakpoints.keys():
        print "  %08X" % bp

def handler_single_step (dbg):
    #print "Inside handler_single_step!"
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        #print "not in current thread?"
        return DBG_CONTINUE

    disasm   = dbg.disasm(dbg.context.Eip)
    #ret_addr = dbg.get_arg(0)

    # if the current instruction is in a system DLL and the return address is not, set a breakpoint on it and continue
    # without single stepping.
    #if dbg.context.Eip > 0x70000000 and ret_addr < 0x70000000:
    #    dbg.bp_set(ret_addr)
    #    return DBG_CONTINUE

    #print "%08x: %s" % (dbg.context.Eip, dbg.disasm(dbg.context.Eip))

    #if dbg.mirror_stack and dbg.context.Eip == dbg.mirror_stack[-1][1]:
    #    dbg.mirror_stack.pop()


    if len(dbg.stack_trace) > 5:
        print "stopping trace when > 5"

        print "Running call stack:"
        for addr in dbg.stack_trace:
            callAddr, callLine = dbg.disasm_around(addr)[4]
            dbg.call_bps.append(callAddr)
            print "Address: 0x%08x" % addr
            if '[' in callLine:
                callLine += " (0x%08x)" % callAddr
            print "  adding BP on %s" % callLine
            dbg.bp_set(callAddr)

        dbg.stack_trace = []
        dbg.single_step(False)
        dbg.bp_del(dbg.ret_addr)
        dbg.bp_del(dbg.func_resolve('ws2_32', 'send'))
        dbg.bp_del(dbg.func_resolve('ws2_32', 'recv'))

        return DBG_CONTINUE

    if disasm.startswith("ret"):
        print "RET @ 0x%08x to 0x%08x" % (dbg.context.Eip, dbg.get_arg(0))
        dbg.stack_trace.append(dbg.get_arg(0))
        dbg.single_step(True)

        print "moving ret_addr to 0x%08x" % dbg.get_arg(0)
        dbg.bp_del(dbg.ret_addr)
        dbg.ret_addr = dbg.get_arg(0)
        dbg.bp_set(dbg.ret_addr)
        return DBG_CONTINUE
        #check_stack_integrity(dbg)

    #if disasm.startswith("call"):
    #    dbg.mirror_stack.append((dbg.context.Esp-4, dbg.context.Eip + dbg.instruction.length))

    dbg.single_step(True)
    return DBG_CONTINUE

def handler_breakpoint (dbg):
    # ignore the first windows driven breakpoint.
    #if pydbg.first_breakpoint:
        #   return DBG_CONTINUE

    buffer = ''
    main_dbg.hide_debugger()

    if not dbg.bp_is_ours(dbg.context.Eip):
        pass
    elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'send'):
        buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
        #Ignore "8" being sent from firefox
        #todo: figure out why that's sent
        info = ('', "\nSEND: \"%s\"" % buffer)[len(buffer) > 1]
        print_state_info(dbg, info)

    elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'recv'):
        buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
        info = ('', "\nRECV: \"%s\"" % buffer)[len(buffer) > 1]
        print_state_info(dbg, info)

    elif dbg.context.Eip == dbg.ret_addr:
        print "breaking on ret_addr: 0x%08x" % dbg.ret_addr
        print "Engage Single Stepping!"
        dbg.monitor_tid = dbg.dbg.dwThreadId
        dbg.single_step(True)

    #We're going to do a call stack trace and put BPs on all the calls before-hand
    elif dbg.context.Eip in dbg.call_bps:
        print "Stack BP at CALL 0x%08x" % dbg.context.Eip
        for arg in range(3):
            try:
                if arg == 0:
                    print "    Return address: 0x%08x" % dbg.get_arg(arg)
                else:
                    print "    Arg[%d]: 0x%08x" % (arg, dbg.get_arg(arg)),
                    print ", deref: %s" % dbg.get_printable_string((dbg.read_process_memory(dbg.get_arg(arg), 256)))
            except Exception, e:
                print e
        dbg.bp_del(dbg.context.Eip)
        dbg.call_bps.remove(dbg.context.Eip)

        if len(dbg.call_bps) == 0:
            #clear out everything
            dbg.call_bps = []
            dbg.ret_addr = 0
            dbg.bp_del_all()
            try:
                addr = int(raw_input("Enter encryption function BP [press Enter to continue search]: "),16)
            except ValueError:
                print "No input received, rehooking send/recv to continue search"
                dbg.bp_set(dbg.func_resolve('ws2_32', 'send'))
                dbg.bp_set(dbg.func_resolve('ws2_32', 'recv'))     
                return DBG_CONTINUE
            
            print "[+] Setting encryption breakpoint at 0x%08x" % addr
            dbg.bp_set(addr)
            dbg.encryption_bps.append(addr)
            return DBG_CONTINUE

            #crashes
            #dbg.detach()
            #print "...well can't detach, hit ctrl c"

    elif dbg.context.Eip in dbg.encryption_bps:
        print "[+] Hit encryption breakpoint at 0x%08x" % dbg.context.Eip
        for arg in range(3):
            try:
                if arg == 0:
                    print "    Return address: 0x%08x" % dbg.get_arg(arg)
                else:
                    print "    Arg[%d]: 0x%08x" % (arg, dbg.get_arg(arg)),
                    print ", deref: %s" % dbg.get_printable_string((dbg.read_process_memory(dbg.get_arg(arg), 256)))
            except Exception, e:
                print e
        return DBG_CONTINUE
    
    elif dbg.context.Eip == EXE_ENTRY:
        print '[+] reached entry point, setting library breakpoints'
        try:
            dbg.bp_set(dbg.func_resolve('ws2_32','send'))
            dbg.bp_set(dbg.func_resolve('ws2_32','recv'))
        except Exception:
            print 'Unable to register some of the library breakpoints'
    else:
        print 'Could not find handler for BP @ 0x%08x' % dbg.context.Eip
        print 'dbg.ret_addr == 0x%08x' % dbg.ret_addr

    #print "ws2_32.send() called from thread %d @%08x" % (pydbg.dbg.dwThreadId, pydbg.exception_address)
    return DBG_CONTINUE

def print_state_info(dbg, info=''):
    entropy = 0
    stack_list = None
    thread_context = None
    dll = None
    return_addr = dbg.get_arg(0)
    buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))

    #Don't print "SEND: 8" for firefox
    if info:
        print info

    entropy = calc_entropy(list(buffer))
    #not enough data to calculate entropy, ignore
    if entropy > 0:
        print "Entropy: %f" % entropy

    if entropy > ENTROPY_LIMIT:
        print "=== ENCRYPTED TRAFFIC ==="
        #todone: Figure out how to get the call stack
        #idea: we're in the wrong thread context (in ws2_32, not PID)
        #      enumerate all threads, find the one where its context.Eip == return value range
        dll = dbg.addr_to_dll(dbg.context.Eip)
        if dll:
            print "Currently in DLL: %s" % dll.name
        print "Return address: 0x%x" % return_addr
        for thread_id in dbg.enumerate_threads():
            thread_context = dbg.get_thread_context(None, thread_id)
            if thread_context:
                print "Thread ID: %d, EIP: 0x%x" % (thread_id, thread_context.Eip)
        stack_list = dbg.stack_unwind()
        '''if stack_list:
            print "Call stack:"
            for return_addr in stack_list:
                print "  0x%x" % return_addr
        else: #try to manually reconstruct the call stack'''
        dbg.ret_addr = dbg.get_arg(0)
        print "[+] Setting BP for ret_addr at 0x%08x" % dbg.ret_addr
        dbg.bp_set(dbg.ret_addr)
        dbg.stack_trace = [] #clear out call stack

        #print "Context: %s" % dbg.dump_context()

def calc_entropy(hex_list):
    #See http://en.wikipedia.org/wiki/Entropy_%28information_theory%29#Definition
    #TODO: Optimize
    entropy = 0.0
    freq = {}
    for byte in hex_list:
        if byte in freq:
            freq[byte] += 1.0
        else:
            freq[byte] = 1.0
    for byte in freq:
        p = freq[byte] * 1.0 / len(hex_list)
        entropy -= p * math.log(p, 256)

    return entropy

if __name__ == '__main__':
    main_dbg = pydbg()
    main_dbg.mirror_stack = []
    main_dbg.stack_trace = []
    main_dbg.monitor_tid  = 0
    main_dbg.start_time   = time.time()
    main_dbg.ret_addr = 0
    main_dbg.call_bps = []
    main_dbg.encryption_bps = []

    #Parse command line arguments
    parser = OptionParser()
    parser.add_option("-a", "--attach", dest="attachName", default='', help="Name/PID of process to attach to")
    parser.add_option("-l", "--load", dest="filepath", default='', help="Path of file to load")

    (options, args) = parser.parse_args()

    if options.attachName:
        #find our process if we want to attach
        foundPID = False
        if options.attachName.isdigit():
            pid = long(options.attachName)
            foundPID = True
        else:
            for (pid, name) in main_dbg.enumerate_processes():
                if name == options.attachName:
                    foundPID = True
                    break

        if foundPID:
            print "[+] Attaching to PID %d" % pid
            main_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
            #register a single stepping handler
            main_dbg.set_callback(EXCEPTION_SINGLE_STEP, handler_single_step)
            main_dbg.attach(pid)
            #try:
            main_dbg.bp_set(main_dbg.func_resolve('ws2_32','send'))
            main_dbg.bp_set(main_dbg.func_resolve('ws2_32','recv'))
            #except:
                #figure out how to report which one failed
                #print 'Unable to register some of the library breakpoints'
            main_dbg.debug_event_loop()
        else:
            print "Could not find process: " + options.attachName

    elif options.filepath:
        #break at entry of loaded file, then break on specific libraries
        print "[+] Loading file at %s" % options.filepath
        EXE_HEAD = pefile.PE(options.filepath)
        EXE_ENTRY = EXE_HEAD.OPTIONAL_HEADER.AddressOfEntryPoint \
              + EXE_HEAD.OPTIONAL_HEADER.ImageBase

        #load our file from disk
        main_dbg.load(options.filepath)

        # register a breakpoint handler function.
        main_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

        #register a single stepping handler
        dbg.set_callback(EXCEPTION_SINGLE_STEP, handler_single_step)

        main_dbg.bp_set(EXE_ENTRY)
        main_dbg.run()
    else:
        print "Error: Specifiy either a process name to attach to or file to load!"
        print "Use -h for help."
        sys.exit()

    #main_dbg.debug_event_loop()