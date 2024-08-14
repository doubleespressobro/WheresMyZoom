using ExileCore;
using System.Runtime.InteropServices;
using System;

namespace WheresMyZoom;

public class WheresMyZoom : BaseSettingsPlugin<WheresMyZoomSettings>
{
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_FREE = 0x00010000;

    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_NOACCESS = 0x01;


    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint size, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    IntPtr baseAddress = IntPtr.Zero;
    IntPtr baseAllocation = IntPtr.Zero;
    nint processHandle = 0;

    IntPtr FindNextFreeMemoryRegion(IntPtr startAddress, uint size)
    {
        MEMORY_BASIC_INFORMATION mbi;
        IntPtr address = startAddress - 0x10000;

        while (VirtualQueryEx(processHandle, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != IntPtr.Zero)
        {
            if (mbi.State == MEM_FREE && mbi.RegionSize.ToInt64() >= size)
            {
                return mbi.BaseAddress;
            }

            address = IntPtr.Add(mbi.BaseAddress, (int)mbi.RegionSize);
        }

        return IntPtr.Zero;
    }

    IntPtr FindUnusedSection(IntPtr startAddress, int maxBytesToCheck, int count)
    {
        const int bufferSize = 4096;
        byte[] buffer = new byte[bufferSize];
        IntPtr address = startAddress;
        int bytesRead;

        while (maxBytesToCheck > 0)
        {
            int bytesToRead = Math.Min(bufferSize, maxBytesToCheck);

            if (!ReadProcessMemory(processHandle, address, buffer, (uint)bytesToRead, out bytesRead))
            {
                DebugWindow.LogError("Failed to read memory. Error: " + Marshal.GetLastWin32Error());
                break;
            }

            int zeroCount = 0;

            for (int i = 0; i < bytesRead; i++)
            {
                if (buffer[i] == 0x00)
                {
                    zeroCount++;
                    if (zeroCount == count)
                    {
                        return IntPtr.Add(address, i - count + 2);
                    }
                }
                else
                {
                    zeroCount = 0;
                }
            }

            address = IntPtr.Add(address, bytesRead);
            maxBytesToCheck -= bytesRead;
        }

        return IntPtr.Zero;
    }

    private void InitializeProcess()
    {
        if (baseAddress == IntPtr.Zero)
        {
            baseAddress = (nint)GameController.Memory.AddressOfProcess;
            processHandle = OpenProcess(0x1F0FFF, false, GameController.Memory.Process.Id);

            baseAllocation = AllocateMemory(baseAddress, 0x1000);
        }
    }

    private IntPtr AllocateMemory(IntPtr baseAddress, uint size)
    {
        IntPtr freeRegion = FindNextFreeMemoryRegion(baseAddress, size);
        if (freeRegion == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find a free memory region.");
            return IntPtr.Zero;
        }

        DebugWindow.LogMsg("Found free memory region at: " + freeRegion.ToString("X"));
        return VirtualAllocEx(processHandle, freeRegion, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    private bool WriteValueToMemory(IntPtr address, float value)
    {
        byte[] valueBytes = BitConverter.GetBytes(value);
        if (!WriteProcessMemory(processHandle, address, valueBytes, (uint)valueBytes.Length, out _))
        {
            DebugWindow.LogError("Failed to write value. Error: " + Marshal.GetLastWin32Error());
            return false;
        }
        return true;
    }

    private bool WriteJumpToMemory(IntPtr originalAddress, long jumpOffset)
    {
        return WriteJumpToMemory(originalAddress, jumpOffset, 1, false);
    }

    private bool WriteJumpToMemory(IntPtr originalAddress, long jumpOffset, int nopSize, bool useCustomNOP)
    {
        Span<byte> jumpInstruction = stackalloc byte[5];
        jumpInstruction[0] = 0xE9;
        BitConverter.TryWriteBytes(jumpInstruction.Slice(1, 4), (int)jumpOffset);

        Span<byte> nopInstruction = stackalloc byte[nopSize];
        if (useCustomNOP)
        {
            nopInstruction = stackalloc byte[4];

            nopInstruction[0] = 0x0F;
            nopInstruction[1] = 0x1F;
            nopInstruction[2] = 0x40;
            nopInstruction[3] = 0x00;
        }
        else
        {
            for (int i = 0; i < nopSize; i++)
            {
                nopInstruction[i] = 0x90;
            }
        }

        if (!WriteProcessMemory(processHandle, originalAddress, jumpInstruction.ToArray(), (uint)jumpInstruction.Length, out _))
        {
            DebugWindow.LogError($"Failed to write jump to memory. Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        if (!WriteProcessMemory(processHandle, IntPtr.Add(originalAddress, jumpInstruction.Length), nopInstruction.ToArray(), (uint)nopInstruction.Length, out _))
        {
            DebugWindow.LogError($"Failed to write NOPs to memory. Error: {Marshal.GetLastWin32Error()}");
            return false;
        }

        return true;
    }


    private bool WriteMinssInstruction(IntPtr baseAddress, IntPtr patchAddress, IntPtr origAddress)
    {
        long relativeValueAddr = baseAddress.ToInt64() - IntPtr.Add(patchAddress, 8).ToInt64();
        long relativeJumpBackAddr = origAddress.ToInt64() + 3 - IntPtr.Add(patchAddress, 8).ToInt64();

        Span<byte> newCode = stackalloc byte[13];
        newCode[0] = 0xF3;
        newCode[1] = 0x0F;
        newCode[2] = 0x5D;
        newCode[3] = 0x0D;

        BitConverter.TryWriteBytes(newCode.Slice(4, 4), (int)relativeValueAddr);

        newCode[8] = 0xE9;
        BitConverter.TryWriteBytes(newCode.Slice(9, 4), (int)relativeJumpBackAddr);

        return WriteProcessMemory(processHandle, patchAddress, newCode.ToArray(), (uint)newCode.Length, out _)
            || LogWriteError();
    }

    private bool LogWriteError()
    {
        DebugWindow.LogError("Failed to write memory. Error: " + Marshal.GetLastWin32Error());
        return false;
    }


    private void ApplyFogPatch(IntPtr baseAddress, int instructionOffset, int memoryOffset)
    {
        IntPtr fogMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (fogMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = IntPtr.Add(baseAddress, instructionOffset);
        long jumpToNewCodeRelative = WriteFogPatch(fogMemoryAllocation, originalInstructionAddress, memoryOffset);

        if (jumpToNewCodeRelative == 0) return;

        IntPtr patchAddress = originalInstructionAddress;
        if (!WriteJumpToMemory(patchAddress, jumpToNewCodeRelative, 1, false)) return;
    }

    private long WriteFogPatch(IntPtr fogMemoryAllocation, IntPtr originalInstructionAddress, int memoryOffset)
    {
        long relativeAddress = originalInstructionAddress.ToInt64() - IntPtr.Add(fogMemoryAllocation, 9).ToInt64();

        Span<byte> newCode = stackalloc byte[15];

        newCode[0] = 0xC7;
        newCode[1] = 0x86;

        BitConverter.TryWriteBytes(newCode.Slice(2, 4), memoryOffset);

        newCode[6] = 0x00;
        newCode[7] = 0x00;
        newCode[8] = 0x00;
        newCode[9] = 0x00;
        newCode[10] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(11, 4), (int)relativeAddress);

        if (!WriteProcessMemory(processHandle, fogMemoryAllocation, newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError($"Failed to write fog patch at offset 0x{memoryOffset:X}. Error: {Marshal.GetLastWin32Error()}");
            return 0;
        }

        return fogMemoryAllocation.ToInt64() - (originalInstructionAddress.ToInt64() + 5);
    }

    private long WriteBlackBoxPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress, float value)
    {
        if (!WriteValueToMemory(patchMemoryAllocation, value)) return 0;

        IntPtr blackBoxAddress = patchMemoryAllocation;

        int relativeBlackBoxAddress1 = (int)(blackBoxAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 8).ToInt64()) - 5);
        int relativeBlackBoxAddress2 = (int)(blackBoxAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 16).ToInt64()) - 5);

        long relativeReturnAddress = originalInstructionAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 28).ToInt64()) - 4;

        Span<byte> newCode = stackalloc byte[38];

        newCode[0] = 0xF3;
        newCode[1] = 0x0F;
        newCode[2] = 0x10;
        newCode[3] = 0x05;

        BitConverter.TryWriteBytes(newCode.Slice(4, 4), relativeBlackBoxAddress1);

        newCode[8] = 0xF3;
        newCode[9] = 0x0F;
        newCode[10] = 0x10;
        newCode[11] = 0x15;

        BitConverter.TryWriteBytes(newCode.Slice(12, 4), relativeBlackBoxAddress2);

        newCode[16] = 0xF3;
        newCode[17] = 0x0F;
        newCode[18] = 0x11;
        newCode[19] = 0x91;

        BitConverter.TryWriteBytes(newCode.Slice(20, 4), 0x00000264);

        newCode[24] = 0x0F;
        newCode[25] = 0x2E;
        newCode[26] = 0x81;

        BitConverter.TryWriteBytes(newCode.Slice(27, 4), 0x00000264);

        newCode[31] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(32, 4), (int)relativeReturnAddress);

        if (!WriteProcessMemory(processHandle, IntPtr.Add(patchMemoryAllocation, 5), newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError($"Failed to write BlackBox patch. Error: {Marshal.GetLastWin32Error()}");
            return 0;
        }

        return patchMemoryAllocation.ToInt64() - (originalInstructionAddress.ToInt64());
    }

    private void ApplyBlackKillPatch(IntPtr baseAddress, int instructionOffset, float blackKillValue)
    {
        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = IntPtr.Add(baseAddress, instructionOffset);

        long jumpToNewCodeRelative = WriteBlackBoxPatch(patchMemoryAllocation, originalInstructionAddress, blackKillValue);

        if (jumpToNewCodeRelative == 0) return;

        IntPtr patchAddress = originalInstructionAddress;
        if (!WriteJumpToMemory(patchAddress, jumpToNewCodeRelative, 2, true)) return;
    }


    public override void OnLoad()
    {
        Settings.EnableZoom.OnPressed = () =>
        {
            InitializeProcess();

            IntPtr zoomMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
            if (zoomMemoryAllocation == IntPtr.Zero) return;

            if (!WriteValueToMemory(zoomMemoryAllocation, 30.0f)) return;

            IntPtr zoomPatchAddress = IntPtr.Add(zoomMemoryAllocation, sizeof(float) + 2);
            IntPtr patchAddress = IntPtr.Add(baseAddress, 0xE67E1);
            long relativeAddress = zoomPatchAddress.ToInt64() - IntPtr.Add(patchAddress, 5).ToInt64();

            if (!WriteJumpToMemory(patchAddress, relativeAddress, 3, false)) return;

            IntPtr afterMinssAddress = IntPtr.Add(zoomPatchAddress, 5 + 3);
            long zoomH1RelativeAddress = zoomMemoryAllocation.ToInt64() - afterMinssAddress.ToInt64();

            if (!WriteMinssInstruction(zoomMemoryAllocation, zoomPatchAddress, patchAddress)) return;
        };

        Settings.EnableNoFog.OnPressed = () =>
        {
            InitializeProcess();

            ApplyFogPatch(baseAddress, 0xD8BB2C, 0x180);
            ApplyFogPatch(baseAddress, 0xD8BABA, 0x160);
        };

        Settings.EnableNoBlackBox.OnPressed = () =>
        {
            InitializeProcess();

            ApplyBlackKillPatch(baseAddress, 0xCBFCA5, 20000.0f);
        };
    }
}