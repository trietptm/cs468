# Possible solutions handle WSABUF #
  * Defining custom struct for pinvoke http://msdn.microsoft.com/en-us/magazine/cc163910.aspx
  * MSDN Calling Native Functions from Managed Code http://msdn.microsoft.com/en-us/library/ms235282.aspx
  * Walking memory by hand of returned structs http://www.netomatix.com/development/EmbedStruct.aspx
  * Someone with pretty much the exact same question...... structs almost identical to ours http://www.experts-exchange.com/Programming/Languages/C_Sharp/Q_22144270.html

### Old ideas ###
  * Can just use IntPtr as any pointer then Marshal.PtrToStructure - http://msdn.microsoft.com/en-us/library/4ca6d5z7.aspx
  * Some MSDN info http://msdn.microsoft.com/en-us/library/aa446536.aspx