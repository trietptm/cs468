using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;
using EasyHook;
using System.Windows.Forms;


namespace ProcessMonitor
{
    public unsafe struct WSABUF
    {
        public ulong len;
        public char* buf;
    }

    public class DemoInjection : EasyHook.IEntryPoint
    {
        public DemoInterface Interface = null;
        public LocalHook sendHook = null;
        public LocalHook recvHook = null;
        public LocalHook WSASendHook = null;
        Stack<String> QueueSend = new Stack<string>();
        Stack<String> QueueWSASend = new Stack<string>();
        Stack<String> QueueRecv = new Stack<string>();

        public DemoInjection(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            Interface = RemoteHooking.IpcConnectClient<DemoInterface>(InChannelName);

            Interface.Ping(RemoteHooking.GetCurrentProcessId());
        }

        public unsafe void Run(
            RemoteHooking.IContext InContext,
            String InArg1)
        {
            try
            {
                sendHook = LocalHook.Create(
                    LocalHook.GetProcAddress("ws2_32.dll", "send"),
                    new Dsend(send_Hooked),
                    this);

                recvHook = LocalHook.Create(
                    LocalHook.GetProcAddress("ws2_32.dll", "recv"),
                    new Drecv(recv_Hooked),
                    this);

                WSASendHook = LocalHook.Create(
                    LocalHook.GetProcAddress("ws2_32.dll", "WSASend"),
                    new DWSASend(WSASend_Hooked),
                    this);

                /*
                 * Don't forget that all hooks will start deaktivated...
                 * The following ensures that all threads are intercepted:
                 */
                sendHook.ThreadACL.SetExclusiveACL(new Int32[1]);
                recvHook.ThreadACL.SetExclusiveACL(new Int32[1]);
                WSASendHook.ThreadACL.SetExclusiveACL(new Int32[1]);
            }
            catch (Exception e)
            {
                /*
                    Now we should notice our host process about this error...
                 */
                Interface.ReportError(RemoteHooking.GetCurrentProcessId(), e);

                return;
            }


            // wait for host process termination...
            try
            {
                while (Interface.Ping(RemoteHooking.GetCurrentProcessId()))
                {
                    Thread.Sleep(500);

                    // transmit newly monitored file accesses...
                    lock (QueueSend)
                    {
                        if (QueueSend.Count > 0)
                        {
                            String[] Package = null;

                            Package = QueueSend.ToArray();

                            QueueSend.Clear();

                            Interface.OnSend(RemoteHooking.GetCurrentProcessId(), Package);
                        }
                    }

                    lock (QueueRecv)
                    {
                        if (QueueRecv.Count > 0)
                        {
                            String[] Package = null;

                            Package = QueueRecv.ToArray();

                            QueueRecv.Clear();

                            Interface.OnRecv(RemoteHooking.GetCurrentProcessId(), Package);
                        }
                    }

                    lock (QueueWSASend)
                    {
                        if (QueueWSASend.Count > 0)
                        {
                            String[] Package = null;
                            Package = QueueWSASend.ToArray();
                            QueueWSASend.Clear();
                            Interface.OnWSASend(RemoteHooking.GetCurrentProcessId(), Package);
                        }
                    }
                }
            }
            catch
            {
                // NET Remoting will raise an exception if host is unreachable
            }
        }


        /* ------- send() --------- */
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        unsafe delegate Int32 Dsend(Int32 s, IntPtr buf, Int32 len, Int32 flags);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public unsafe static extern Int32 send(Int32 s, IntPtr buf, Int32 len, Int32 flags);


        // this is where we are intercepting all file accesses!
        static unsafe Int32 send_Hooked(Int32 s, IntPtr buf, Int32 len, Int32 flags)
        {
            try
            {
                DemoInjection This = (DemoInjection)HookRuntimeInfo.Callback;
                String buffer = "";
                //char* tempBuf = buf;
                lock (This.QueueSend)
                {
                    if (This.QueueSend.Count < 1000)
                    {
                        buffer = Marshal.PtrToStringAnsi(buf, len);
                        This.QueueSend.Push(buffer);// (buf, char[])[0]).ToString());
                    }
                }
            }
            catch
            {
            }

            // call original API...
            return send(s, buf, len, flags);
        }

        /* ------- recv() --------- */
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        unsafe delegate Int32 Drecv(Int32 s, IntPtr buf, Int32 len, Int32 flags);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public unsafe static extern Int32 recv(Int32 s, IntPtr buf, Int32 len, Int32 flags);


        // this is where we are intercepting all file accesses!
        static unsafe Int32 recv_Hooked(Int32 s, IntPtr buf, Int32 len, Int32 flags)
        {
            try
            {
                DemoInjection This = (DemoInjection)HookRuntimeInfo.Callback;
                String buffer = "";
                //char* tempBuf = buf;
                lock (This.QueueRecv)
                {
                    if (This.QueueRecv.Count < 1000)
                    {
                        buffer = Marshal.PtrToStringAnsi(buf, len);
                        This.QueueRecv.Push(buffer);// (buf, char[])[0]).ToString());
                    }
                }
            }
            catch
            {
            }

            // call original API...
            return recv(s, buf, len, flags);
        }


        /* ------- WSASend() --------- */
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        delegate Int32 DWSASend(Int32 s, IntPtr lpBuffers, UInt32 dwBufferCount, IntPtr lpNumberOfBytesSent,
                                UInt32 dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern Int32 WSASend(Int32 s, IntPtr lpBuffers, UInt32 dwBufferCount, IntPtr lpNumberOfBytesSent,
                                UInt32 dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);


        // this is where we are intercepting all file accesses!
        static unsafe Int32 WSASend_Hooked(Int32 s, IntPtr lpBuffers, UInt32 dwBufferCount, IntPtr lpNumberOfBytesSent,
                                UInt32 dwFlags, IntPtr lpOverlapped, IntPtr lpCompletionRoutine)
        {
            try
            {
                DemoInjection This = (DemoInjection)HookRuntimeInfo.Callback;

                lock (This.QueueWSASend)
                {
                    WSABUF buffer = new WSABUF();
                    Marshal.PtrToStructure(lpBuffers, buffer);
                    if (This.QueueWSASend.Count < 1000)
                        This.QueueWSASend.Push(Marshal.PtrToStringAnsi((IntPtr)buffer.buf, (int)buffer.len));
                }
            }
            catch
            {
            }

            // call original API...
            return WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                                dwFlags, lpOverlapped, lpCompletionRoutine);
        }
    }
}
