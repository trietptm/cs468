Tried to put memory breakpoints on the buffers used to see if the data is later decrypted.  Never was able to get memory BPs to actually trigger.  I think this may be because I am trying to create the BPs when I'm inside of the send/recv code which is in ws2\_32.dll and not the process we are monitoring.  Not sure how to fix this.

Guy who wrote paimei also has this script for checking stack integrity... maybe we could do something similar, shows how to single step looking for call/rets to manage our own stack http://dvlabs.tippingpoint.com/pub/pamini/stack_integrity_monitor.py

Tried HW breakpoints but just registering a callback cause the HW BP to trigger all the time and lock the program up.

## Enable Logging with PyDbg ##
  * If you want to enable the PyDbg logging, change line 144 of pydbg.py to use sys.stderr.write() instead of None.  This requires a reinstall w/ setup.py (or you could just change it in python26/lib/site-packages/pydbg)