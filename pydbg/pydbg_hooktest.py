from pydbg import *
from pydbg.defines import *
import pefile
import sys
import signal
import math
import time
import re
from optparse import OptionParser

#COMPLETELY ARBITRARY FOR NOW
ENTROPY_LIMIT = 0.80
EXE_ENTRY = None
CALL_STACK_SIZE = 5

def print_bps(dbg):
    print "BPS: "
    for bp in dbg.breakpoints.keys():
        print "  %08X" % bp

def handler_single_step (dbg):
    #print "Inside handler_single_step!"
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        #print "not in current thread?"
        return DBG_CONTINUE
    
    elif len(dbg.encryption_bps) > 0 or not dbg.trace_calls:
        # Some reason it kicks into this handler sometimes... so if we have
        # some encryption bps set, just get out of it
        dbg.single_step(False)
        return DBG_CONTINUE
        
    disasm   = dbg.disasm(dbg.context.Eip)

    if len(dbg.stack_trace) > CALL_STACK_SIZE:
        print "  [i] Stopping trace, call stack size reached", CALL_STACK_SIZE
        dbg.trace_calls = False

        #print "Running call stack:"
        for addr in dbg.stack_trace:
            callAddr, callLine = dbg.disasm_around(addr)[4]
            dbg.call_bps.append(callAddr)
            print "    [i] Breakpoint set at 0x%08x" % addr
            dbg.bp_set(callAddr)

        dbg.stack_trace = []
        dbg.single_step(False)
        dbg.bp_del(dbg.ret_addr)
        dbg.bp_del(dbg.func_resolve('ws2_32', 'send'))
        dbg.bp_del(dbg.func_resolve('ws2_32', 'recv'))
        
        return DBG_CONTINUE

    if disasm.startswith("ret"):
        #print "    - RET @ 0x%08x to 0x%08x" % (dbg.context.Eip, dbg.get_arg(0)),
        dbg.stack_trace.append(dbg.get_arg(0))
        dbg.single_step(True)

        #print " moving ret_addr to 0x%08x" % dbg.get_arg(0)
        dbg.bp_del(dbg.ret_addr)
        dbg.ret_addr = dbg.get_arg(0)
        dbg.bp_set(dbg.ret_addr)
        
        return DBG_CONTINUE
        
    dbg.single_step(True)
    return DBG_CONTINUE
    
#dump stack args when looking for new encryption functions
def dump_stack_args(dbg):
    for arg in range(1, 3):
        try:
            if arg == 0:
                print "    Return address: 0x%08x" % dbg.get_arg(arg)
            else:
                stack_arg = dbg.get_arg(arg)
                print "    Arg[%d]: 0x%08x, deref: " % (arg, stack_arg),
                
                # This helps eliminate some of the read_proc_mem errors by
                # not trying for some arguments...
                if stack_arg == 0x0:
                    print "(null)"
                elif stack_arg < 0xFFFF:
                    print "(buffer size or some flags?)"
                else:
                    print dbg.get_printable_string((dbg.read_process_memory(dbg.get_arg(arg), 256)))
                print
        except Exception, e:
            print e

#print out the specified encryption function arguments
def dump_encryption_args(dbg):
    arg_buf = dbg.encryption_bps[dbg.context.Eip]['buffer']
    arg_size = dbg.encryption_bps[dbg.context.Eip]['size']
    #print "all" arguments unless specified
    if arg_buf == -1:
        for arg in range(3):
            try:
                if arg == 0:
                    print "    Return address: 0x%08x" % dbg.get_arg(arg)
                else:
                    stack_arg = dbg.get_arg(arg)
                    print "    Arg[%d]: 0x%08x, deref: " % (arg, stack_arg),
                    
                    # This helps eliminate some of the read_proc_mem errors by
                    # not trying for some arguments...
                    if stack_arg == 0x0:
                        print "(null)"
                    elif stack_arg < 0xFFFF:
                        print "(buffer size or some flags?)"
                    else:
                        print dbg.get_printable_string((dbg.read_process_memory(dbg.get_arg(arg), 256)))
            except Exception, e:
                print e
    else:
        buffer = dbg.get_arg(arg_buf)
        if arg_size == -1:
            print dbg.get_printable_string((dbg.read_process_memory(buffer, 256)))
        else:
            size = dbg.get_arg(arg_size)
            print dbg.get_printable_string((dbg.read_process_memory(buffer, size)))
                
def handler_breakpoint (dbg):
    # ignore the first windows driven breakpoint.
    #if pydbg.first_breakpoint:
        #   return DBG_CONTINUE

    buffer = ''
    main_dbg.hide_debugger()
    
    if not dbg.bp_is_ours(dbg.context.Eip):
        pass
        
    elif dbg.context.Eip in dbg.encryption_bps:
        print "*-*-*-*-*------------------*-*-*-*-*------------------*-*-*-*-*"
        print "[+] Hit encryption breakpoint at 0x%08x" % dbg.context.Eip
        dump_encryption_args(dbg)
        return DBG_CONTINUE
        
    elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'send'):
        buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
        #Ignore "8" being sent from firefox
        #todo: figure out why that's sent
        info = ''
        if len(buffer) > 1:
            print "---------------------------------------------------------------"
            print "[+] Hit ws2_32.send at 0x%08x" % dbg.context.Eip
            info = "  [*] SEND: \"%s\"" % buffer
            
        print_state_info(dbg, info)

    elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'recv'):
        buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
        info = ''
        if len(buffer) > 1:
            print "---------------------------------------------------------------"
            print "[+] Hit ws2_32.recv at 0x%08x" % dbg.context.Eip
            info = "  [*] RECV: \"%s\"" % buffer
            
        print_state_info(dbg, info)

    elif dbg.context.Eip == dbg.ret_addr:
        #print "Breaking on ret_addr: 0x%08x, single stepping..." % dbg.ret_addr
        dbg.monitor_tid = dbg.dbg.dwThreadId
        dbg.single_step(True)

    #We're going to do a call stack trace and put BPs on all the calls before-hand
    elif dbg.context.Eip in dbg.call_bps:
        print "---------------------------------------------------------------"
        print "[+] Hit Stack BP at CALL 0x%08x\n" % dbg.context.Eip
        dump_stack_args(dbg)

        dbg.bp_del(dbg.context.Eip)
        dbg.call_bps.remove(dbg.context.Eip)
        
        if len(dbg.call_bps) == 0:
            #clear out everything
            dbg.call_bps = []
            dbg.ret_addr = 0
            dbg.bp_del_all()
            
            dbg.encryption_bps = {}
            cur_addr = None
            print "=== Select Encryption Function Breakpoints ==="
            #TODO: optimize/clean up this loop
            while cur_addr != '':
                cur_addr = raw_input("Enter encryption function BP [Press Enter to continue search]: ")
                if(cur_addr == '' or cur_addr == 'q'):
                    print "No input received, rehooking send/recv to continue search"
                    dbg.bp_set(dbg.func_resolve('ws2_32', 'send'))
                    dbg.bp_set(dbg.func_resolve('ws2_32', 'recv'))
                    dbg.get_stack = True
                    return DBG_CONTINUE
                else:
                    cur_addr = int(cur_addr, 16)
                    cur_buffer = raw_input("Enter buffer argument number [Press Enter to always print all args]: ")
                    if cur_buffer == '':
                        dbg.encryption_bps[cur_addr] = {'buffer': -1, 'size': -1}
                    else:
                        cur_size = raw_input("Enter size argument number [Press Enter to always print all args]: ")
                        if cur_size != '':
                            dbg.encryption_bps[cur_addr] = {'buffer': int(cur_buffer), 'size': int(cur_size)}
                        else:
                            dbg.encryption_bps[cur_addr] = {'buffer': -1, 'size': -1}
                    dbg.bp_set(cur_addr)
                            
            # loop through all addr...
            '''addrs = re.sub('\s', '', addrs)
            for addr in addrs.split(','):
                # reminder - addr is a string '0xdead', pydbg expects dword
                print "[+] Setting encryption breakpoint at %s" % addr
                dbg.bp_set(int(addr, 16))
                print "set..."
                dbg.encryption_bps.append(int(addr, 16))
                print "appended..."'''
                
            # reset the send so we can compare what we've set bp's on with
            # the actual data sent
            dbg.bp_set(dbg.func_resolve('ws2_32', 'send'))
            
            return DBG_CONTINUE
        else:
            print "[-] Waiting for", len(dbg.call_bps), "more CALL BPs to be hit"
            
    elif dbg.context.Eip == EXE_ENTRY:
        print '[+] reached entry point, setting library breakpoints'
        try:
            dbg.bp_set(dbg.func_resolve('ws2_32','send'))
            dbg.bp_set(dbg.func_resolve('ws2_32','recv'))
        except Exception:
            print 'Unable to register some of the library breakpoints'
    else:
        print 'Could not find handler for BP @ 0x%08x' % dbg.context.Eip
        #print 'dbg.ret_addr == 0x%08x' % dbg.ret_addr

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
        print dbg.get_printable_string(info)
    
    if len(dbg.encryption_bps) > 0 or not dbg.get_stack:
        return
        
    entropy = calc_entropy(list(buffer))
    if entropy > dbg.entropyCutoff:
        print "[!] Entropy: %f" % entropy, " ENCRYPTED TRAFFIC"
        dll = dbg.addr_to_dll(dbg.context.Eip)
        if dll:
            print "  [i] Currently in DLL: %s" % dll.name
        #print "Return address: 0x%x" % return_addr
        
        #idea: we're in the wrong thread context (in ws2_32, not PID)
        #      enumerate all threads, find the one where its context.Eip == return value range
        for thread_id in dbg.enumerate_threads():
            thread_context = dbg.get_thread_context(None, thread_id)
            
        '''stack_list = dbg.stack_unwind()
        if stack_list:
            print "Call stack:"
            for return_addr in stack_list:
                print "  0x%x" % return_addr
        else: #try to manually reconstruct the call stack'''
        dbg.ret_addr = dbg.get_arg(0)
        #print "[+] Setting BP for ret_addr at 0x%08x" % dbg.ret_addr
        dbg.bp_set(dbg.ret_addr)
        dbg.stack_trace = [] #clear out call stack
        dbg.get_stack = False
    elif entropy > 0:
        print "Entropy: %f < %f, Traffic doesn't appear to be encrypted" % (entropy, dbg.entropyCutoff)
        
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
    main_dbg.get_stack = True
    main_dbg.trace_calls = True

    #Parse command line arguments
    parser = OptionParser()
    parser.add_option("-a", "--attach", dest="attachName", default='', help="Name/PID of process to attach to")
    parser.add_option("-l", "--load", dest="filepath", default='', help="Path of file to load")
    parser.add_option("-e", "--entropy-cutoff", type= "float", dest="entropy", default=ENTROPY_LIMIT, help="Traffic with entropy above this level is assumed to be encrypted (0 - 1) defaults to .8")
    
    (options, args) = parser.parse_args()
    main_dbg.entropyCutoff = options.entropy
    
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
