# Oddities about Hooking #
  * The ProcMon sample I'm editing doesn't seem to remove hooks properly.  This means that when you run ProcMon a 2nd time (after recompiling w/ changes) you will probably actually be working w/ the previously injected DLL.  Solution: restart the program you want to monitor each time.

  * GetProcAddress will give a runtime error when hooking some processes.  I think this is b/c the process didn't originally import the function you're trying to hook but I might have just coded something wrong.