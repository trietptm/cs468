from pydbg import *
from pydbg.defines import *
import pefile
import sys
import signal
import math
from optparse import OptionParser

ENTROPY_LIMIT = 0.80

def handler_breakpoint (dbg):
   # ignore the first windows driven breakpoint.
   #if pydbg.first_breakpoint:
	#   return DBG_CONTINUE
   
   buffer = ''
   entropy = 0

   if not dbg.bp_is_ours(dbg.context.Eip):
      pass
   elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'send'):
      buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
      entropy = calc_entropy(list(buffer))
      print "\nSEND: %s" % buffer
      if entropy > ENTROPY_LIMIT:
         print "=== ENCRYPTED TRAFFIC ==="
      print "Entropy: %f" % entropy
   elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'recv'):
      buffer = dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
      entropy = calc_entropy(list(buffer))
      print "\nRECV: %s" % buffer
      if entropy > ENTROPY_LIMIT:
         print "=== ENCRYPTED TRAFFIC ==="
      print "Entropy: %f" % entropy
   elif dbg.context.Eip == EXE_ENTRY:
      print '[+] reached entry point, setting library breakpoints'
      try:
         dbg.bp_set(dbg.func_resolve('ws2_32','send'))
         dbg.bp_set(dbg.func_resolve('ws2_32','recv'))
      except Exception:
         print 'Unable to register some of the library breakpoints'
   else:
      print 'What?'
   
   #print "ws2_32.send() called from thread %d @%08x" % (pydbg.dbg.dwThreadId, pydbg.exception_address)
   return DBG_CONTINUE

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
      #print "sum %d" % sum
      #print "freq[%s] %d" % (byte, freq[byte])
      p = freq[byte] * 1.0 / len(hex_list)
      entropy -= p * math.log(p, 256)
      
   return entropy
   
if __name__ == '__main__':
   main_dbg = pydbg()
   
   #Parse command line arguments
   parser = OptionParser()
   parser.add_option("-a", "--attach", dest="attachName", default='', help="Name of process to attach to")
   parser.add_option("-l", "--load", dest="filepath", default='', help="Path of file to load")

   (options, args) = parser.parse_args()
   
   if options.attachName:
      #find our process if we want to attach
      for (pid, name) in main_dbg.enumerate_processes():
         if name == options.attachName:
            break
      print "[+] Attaching to PID %d" % pid
      main_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
      main_dbg.attach(pid)
      #try:
      main_dbg.bp_set(main_dbg.func_resolve('ws2_32','send'))
      main_dbg.bp_set(main_dbg.func_resolve('ws2_32','recv'))
      #except:
         #figure out how to report which one failed
         #print 'Unable to register some of the library breakpoints'
      main_dbg.debug_event_loop()
      
   elif options.filepath:
      #break at entry of loaded file, then break on specific libraries
      EXE_HEAD = pefile.PE(options.filepath)
      EXE_ENTRY = EXE_HEAD.OPTIONAL_HEADER.AddressOfEntryPoint \
            + EXE_HEAD.OPTIONAL_HEADER.ImageBase
            
      #load our file from disk               
      main_dbg.load(options.filepath)

      # register a breakpoint handler function.
      main_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
      main_dbg.bp_set(EXE_ENTRY)
      main_dbg.run()
   else:
      print "Error: Specifiy either a process name to attach to or file to load!"
      print "Use -h for help."
      sys.exit()

   #main_dbg.debug_event_loop()
