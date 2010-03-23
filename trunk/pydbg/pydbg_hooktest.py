from pydbg import *
from pydbg.defines import *
import pefile
import sys
import signal

PATH_TO_EXE = 'C:\\Program Files\\Mozilla Firefox\\firefox.exe'
#PATH_TO_EXE = 'C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE'

EXE_HEAD = pefile.PE(PATH_TO_EXE)
EXE_ENTRY = EXE_HEAD.OPTIONAL_HEADER.AddressOfEntryPoint \
            + EXE_HEAD.OPTIONAL_HEADER.ImageBase

def handler_breakpoint (dbg):
   # ignore the first windows driven breakpoint.
   #if pydbg.first_breakpoint:
	#   return DBG_CONTINUE

   if not dbg.bp_is_ours(dbg.context.Eip):
      pass
   elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'send'):
      print "\nSEND: buffer data: %s" % dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
   elif dbg.context.Eip == dbg.func_resolve('ws2_32', 'recv'):
      print "\nRECV: buffer data: %s" % dbg.read_process_memory(dbg.get_arg(2), dbg.get_arg(3))
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

if __name__ == '__main__':
   main_dbg = pydbg()

   #How do we handle CTRL-C?
   #signal.signal(signal.SIGINT, dbg.sigint_handler)

   #find our process if we want to attach
   '''for (pid, name) in dbg.enumerate_processes():
      if name == "firefox.exe":
         break

   dbg.attach(pid)'''

   #load our file from disk               
   main_dbg.load(PATH_TO_EXE)

   # register a breakpoint handler function.
   main_dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
   main_dbg.bp_set(EXE_ENTRY)
   main_dbg.run()

   #main_dbg.debug_event_loop()
