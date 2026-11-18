using ExileCore;
using System.Runtime.InteropServices;
using System;
using System.Numerics;
using System.Linq;

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
    SigScanSharp SigScan;

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
                        return IntPtr.Add(address, i - count + 1);
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

            SigScan = new SigScanSharp(processHandle);
            SigScan.SelectModule(GameController.Memory.Process.Modules[0]);
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

    private bool WriteVector4ToMemory(IntPtr address, Vector4 value)
    {
        byte[] valueBytes = BitConverter.GetBytes(value.X)
            .Concat(BitConverter.GetBytes(value.Y))
            .Concat(BitConverter.GetBytes(value.Z))
            .Concat(BitConverter.GetBytes(value.W))
            .ToArray();

        if (!WriteProcessMemory(processHandle, address, valueBytes, (uint)valueBytes.Length, out _))
        {
            DebugWindow.LogError("Failed to write vector. Error: " + Marshal.GetLastWin32Error());
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

            if (nopSize == 4)
            {
                nopInstruction[0] = 0x0F;
                nopInstruction[1] = 0x1F;
                nopInstruction[2] = 0x40;
                nopInstruction[3] = 0x00;
            }
            else if(nopSize == 3)
            {
                nopInstruction[0] = 0x0F;
                nopInstruction[1] = 0x1F;
                nopInstruction[2] = 0x00;
            }
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

        Span<byte> newCode = stackalloc byte[14];
        newCode[0] = 0xF3;
        newCode[1] = 0x0F;
        newCode[2] = 0x5D;
        newCode[3] = 0x0D;

        BitConverter.TryWriteBytes(newCode.Slice(4, 4), (int)relativeValueAddr);

        newCode[8] = 0xE9;
        BitConverter.TryWriteBytes(newCode.Slice(9, 4), (int)relativeJumpBackAddr);

        newCode[13] = 0xC3;

        return WriteProcessMemory(processHandle, patchAddress, newCode.ToArray(), (uint)newCode.Length, out _)
            || LogWriteError();
    }

    private bool LogWriteError()
    {
        DebugWindow.LogError("Failed to write memory. Error: " + Marshal.GetLastWin32Error());
        return false;
    }

    // Reads the [reg+disp32] memory operand of the instruction a patch replaces, so the patch writes the
    // same field the game does. Game updates move these fields and change the base register.
    private bool TryReadMemoryOperand(IntPtr address, ReadOnlySpan<byte> opcode, out int baseRegister, out int displacement)
    {
        baseRegister = 0;
        displacement = 0;

        byte[] bytes = new byte[opcode.Length + 5];
        if (!ReadProcessMemory(processHandle, address, bytes, (uint)bytes.Length, out int bytesRead) || bytesRead != bytes.Length)
        {
            DebugWindow.LogError("Failed to read instruction. Error: " + Marshal.GetLastWin32Error());
            return false;
        }

        byte modRm = bytes[opcode.Length];
        bool isRegPlusDisp32 = (modRm & 0xC0) == 0x80 && (modRm & 0x07) != 0x04;
        if (!bytes.AsSpan(0, opcode.Length).SequenceEqual(opcode) || !isRegPlusDisp32)
        {
            DebugWindow.LogError($"Unexpected instruction at {address:X} (already patched?).");
            return false;
        }

        baseRegister = modRm & 0x07;
        displacement = BitConverter.ToInt32(bytes, opcode.Length + 1);
        return true;
    }

    private void ApplyZoomPatch()
    {
        /* 
            .text:00000000000E67E1                 minss   xmm1, cs:Y
            .text:00000000000E67E9                 movss   dword ptr [rdi+450h], xmm1
            .text:00000000000E67F1
            .text:00000000000E67F1 loc_E67F1:                              ; CODE XREF: sub_E6610+1B0↑j
            .text:00000000000E67F1                 mov     byte ptr [rsi], 1
        */

        IntPtr zoomMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (zoomMemoryAllocation == IntPtr.Zero) return;

        if (!WriteValueToMemory(zoomMemoryAllocation, 30.0f)) return;

        IntPtr zoomPatchAddress = IntPtr.Add(zoomMemoryAllocation, sizeof(float) + 2);

        IntPtr patchAddress = (nint)SigScan.FindPattern("F3 0F 5D ? ? ? ? ? F3 0F 11 ? ? ? ? ? C6", out _);
        if (patchAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find zoom patch address.");
            return;
        }

        long relativeAddress = zoomPatchAddress.ToInt64() - IntPtr.Add(patchAddress, 5).ToInt64();

        if (!WriteJumpToMemory(patchAddress, relativeAddress, 3, false)) return;

        IntPtr afterMinssAddress = IntPtr.Add(zoomPatchAddress, 5 + 3);
        long zoomH1RelativeAddress = zoomMemoryAllocation.ToInt64() - afterMinssAddress.ToInt64();

        if (!WriteMinssInstruction(zoomMemoryAllocation, zoomPatchAddress, patchAddress)) return;
    }


    private void ApplyFogPatch1()
    {
        /*
            .text:00000000010289A7 88 87 30 01 00 00                       mov     byte ptr [rdi+130h], al
            .text:00000000010289AD 41 8B 87 A0 03 00 00                    mov     eax, dword ptr [r15+3A0h]
            .text:00000000010289B4 F2 41 0F 10 87 98 03 00 00              movsd   xmm0, qword ptr [r15+398h]
            .text:00000000010289BD F2 0F 11 87 44 01 00 00                 movsd   qword ptr [rdi+144h], xmm0
            .text:00000000010289C5 89 87 4C 01 00 00                       mov     dword ptr [rdi+14Ch], eax
        */

        IntPtr fogMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (fogMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("88 87 30 01 00 00 41 8B 87", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find fog signature 1.");
            return;
        }

        if (!TryReadMemoryOperand(originalInstructionAddress, [0x88], out int baseRegister, out int memoryOffset)) return;

        long jumpToNewCodeRelative = WriteFogPatch(fogMemoryAllocation, originalInstructionAddress, baseRegister, memoryOffset);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 1, false)) return;
    }

    private void ApplyFogPatch2()
    {
        /*
            .text:0000000001028932 88 87 10 01 00 00                       mov     byte ptr [rdi+110h], al
            .text:0000000001028938 41 8B 87 90 03 00 00                    mov     eax, dword ptr [r15+390h]
            .text:000000000102893F F2 41 0F 10 87 88 03 00 00              movsd   xmm0, qword ptr [r15+388h]
            .text:0000000001028948 F2 0F 11 87 24 01 00 00                 movsd   qword ptr [rdi+124h], xmm0
            .text:0000000001028950 89 87 2C 01 00 00                       mov     dword ptr [rdi+12Ch], eax
        */

        IntPtr fogMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (fogMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("88 87 10 01 00 00 41 8B 87", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find fog signature 2.");
            return;
        }

        if (!TryReadMemoryOperand(originalInstructionAddress, [0x88], out int baseRegister, out int memoryOffset)) return;

        long jumpToNewCodeRelative = WriteFogPatch(fogMemoryAllocation, originalInstructionAddress, baseRegister, memoryOffset);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 1, false)) return;
    }

    private long WriteFogPatch(IntPtr fogMemoryAllocation, IntPtr originalInstructionAddress, int baseRegister, int memoryOffset)
    {
        long relativeAddress = originalInstructionAddress.ToInt64() - IntPtr.Add(fogMemoryAllocation, 9).ToInt64();

        Span<byte> newCode = stackalloc byte[16];

        // mov dword ptr [reg+memoryOffset], 0
        newCode[0] = 0xC7;
        newCode[1] = (byte)(0x80 | baseRegister);

        BitConverter.TryWriteBytes(newCode.Slice(2, 4), memoryOffset);

        newCode[6] = 0x00;
        newCode[7] = 0x00;
        newCode[8] = 0x00;
        newCode[9] = 0x00;
        newCode[10] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(11, 4), (int)relativeAddress);

        newCode[15] = 0xC3;

        if (!WriteProcessMemory(processHandle, fogMemoryAllocation, newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError($"Failed to write fog patch at offset 0x{memoryOffset:X}. Error: {Marshal.GetLastWin32Error()}");
            return 0;
        }

        return fogMemoryAllocation.ToInt64() - (originalInstructionAddress.ToInt64() + 5);
    }

    private long WriteNoBlackBoxPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress, float value, int baseRegister, int memoryOffset)
    {
        if (!WriteValueToMemory(patchMemoryAllocation, value)) return 0;

        IntPtr blackBoxAddress = patchMemoryAllocation;

        int relativeBlackBoxAddress1 = (int)(blackBoxAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 8).ToInt64()) - 5);
        int relativeBlackBoxAddress2 = (int)(blackBoxAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 16).ToInt64()) - 5);

        long relativeReturnAddress = originalInstructionAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 28).ToInt64()) - 4;

        Span<byte> newCode = stackalloc byte[37];

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

        // movss dword ptr [reg+memoryOffset], xmm2
        newCode[16] = 0xF3;
        newCode[17] = 0x0F;
        newCode[18] = 0x11;
        newCode[19] = (byte)(0x90 | baseRegister);

        BitConverter.TryWriteBytes(newCode.Slice(20, 4), memoryOffset);

        // ucomiss xmm0, dword ptr [reg+memoryOffset]
        newCode[24] = 0x0F;
        newCode[25] = 0x2E;
        newCode[26] = (byte)(0x80 | baseRegister);

        BitConverter.TryWriteBytes(newCode.Slice(27, 4), memoryOffset);

        newCode[31] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(32, 4), (int)relativeReturnAddress);

        newCode[36] = 0xC3;

        if (!WriteProcessMemory(processHandle, IntPtr.Add(patchMemoryAllocation, 5), newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError($"Failed to write BlackBox patch. Error: {Marshal.GetLastWin32Error()}");
            return 0;
        }

        return (patchMemoryAllocation.ToInt64() + 1) - (originalInstructionAddress.ToInt64());
    }

    private void ApplyNoBlackBoxPatch(float blackKillValue)
    {
        /*
            .text:0000000001031C95 0F 2E 81 54 02 00 00                    ucomiss xmm0, dword ptr [rcx+254h]
            .text:0000000001031C9C 75 09                                   jnz     short loc_1031CA7
            .text:0000000001031C9E 0F 2E 89 50 02 00 00                    ucomiss xmm1, dword ptr [rcx+250h]
            .text:0000000001031CA5 74 15                                   jz      short locret_1031CBC
            .text:0000000001031CA7
            .text:0000000001031CA7                         loc_1031CA7:
            .text:0000000001031CA7 F3 0F 11 89 50 02 00 00                 movss   dword ptr [rcx+250h], xmm1
            .text:0000000001031CAF F3 0F 11 91 54 02 00 00                 movss   dword ptr [rcx+254h], xmm2
        */

        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("0F 2E 81 54 02 00 00 75 09 0F 2E 89 50 02 00 00", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find no black box signature.");
            return;
        }

        if (!TryReadMemoryOperand(originalInstructionAddress, [0x0F, 0x2E], out int baseRegister, out int memoryOffset)) return;

        long jumpToNewCodeRelative = WriteNoBlackBoxPatch(patchMemoryAllocation, originalInstructionAddress, blackKillValue, baseRegister, memoryOffset);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 4, true)) return;
    }

    private long WriteFastZoomPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress)
    {
        long relativeReturnAddress = (originalInstructionAddress.ToInt64() + 8) - (patchMemoryAllocation.ToInt64() + 21);

        Span<byte> newCode = stackalloc byte[22];

        // movss dword ptr [rdi+498h], xmm1 (target zoom)
        newCode[0] = 0xF3;
        newCode[1] = 0x0F;
        newCode[2] = 0x11;
        newCode[3] = 0x8F;

        BitConverter.TryWriteBytes(newCode.Slice(4, 4), 0x00000498);

        // movss dword ptr [rdi+490h], xmm1 (current zoom, so it doesn't ease towards the target)
        newCode[8] = 0xF3;
        newCode[9] = 0x0F;
        newCode[10] = 0x11;
        newCode[11] = 0x8F;

        BitConverter.TryWriteBytes(newCode.Slice(12, 4), 0x00000490);

        newCode[16] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(17, 4), (int)relativeReturnAddress);

        newCode[21] = 0xC3;

        if (!WriteProcessMemory(processHandle, patchMemoryAllocation, newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError($"Failed to write Fast Zoom patch. Error: {Marshal.GetLastWin32Error()}");
            return 0;
        }

        return patchMemoryAllocation.ToInt64() - (originalInstructionAddress.ToInt64() + 5);
    }


    private void ApplyFastZoomPatch()
    {
        /*
            .text:000000000011B1C2 F3 0F 5D 0D ? ? ? ?                     minss   xmm1, cs:Y
            .text:000000000011B1CA F3 0F 11 8F 98 04 00 00                 movss   dword ptr [rdi+498h], xmm1
            .text:000000000011B1D2 C6 06 01                                mov     byte ptr [rsi], 1

            Current (smoothed) zoom is [rdi+490h]: see "lea rsi, [rdi+490h]" just before the NoSmooth signature.
        */

        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("F3 0F 11 8F 98 04 00 00", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find fast zoom signature.");
            return;
        }

        long jumpToNewCodeRelative = WriteFastZoomPatch(patchMemoryAllocation, originalInstructionAddress);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 3, true)) return;
    }

    private long WriteIncrementalZoomPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress, float value)
    {
        if (!WriteValueToMemory(patchMemoryAllocation, 0.5f))
        {
            DebugWindow.LogError("Failed to write zoom value.");
            return 0;
        }

        IntPtr valueAddress = patchMemoryAllocation;

        int relativeValueAddress = (int)(valueAddress.ToInt64() - (IntPtr.Add(patchMemoryAllocation, 8).ToInt64()) - 0x5);
        long relativeReturnAddress = (originalInstructionAddress.ToInt64() + 3) - (patchMemoryAllocation.ToInt64() + 13);

        Span<byte> newCode = stackalloc byte[14];

        newCode[0] = 0xF3;
        newCode[1] = 0x0F;
        newCode[2] = 0x59;
        newCode[3] = 0x0D;

        BitConverter.TryWriteBytes(newCode.Slice(4, 4), relativeValueAddress);

        newCode[8] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(9, 4), (int)relativeReturnAddress);

        newCode[13] = 0xC3;

        if (!WriteProcessMemory(processHandle, IntPtr.Add(patchMemoryAllocation, 5), newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError("Failed to write zoom patch.");
            return 0;
        }

        return (patchMemoryAllocation.ToInt64() + 5) - (originalInstructionAddress.ToInt64() + 5);
    }

    private void ApplyIncrementalZoomPatch()
    {
        /*
            .text:00000000000E67CD                 mulss   xmm1, cs:dword_2DBAF00
            .text:00000000000E67D5                 addss   xmm1, dword ptr [rdi+450h]
            .text:00000000000E67DD                 maxss   xmm1, xmm0
            .text:00000000000E67E1                 minss   xmm1, cs:Y
            .text:00000000000E67E9                 movss   dword ptr [rdi+450h], xmm1
        */

        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("F3 0F 59 0D ? ? ? ? F3 0F 58 8F ? ? ? ? F3 0F 5F", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find incremental zoom signature.");
            return;
        }

        long jumpToNewCodeRelative = WriteIncrementalZoomPatch(patchMemoryAllocation, originalInstructionAddress, 0.5f);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 3, true))
        {
            DebugWindow.LogError("Failed to write jump to memory.");
            return;
        }
    }

    private long WriteNoSmoothPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress)
    {
        long relativeReturnAddress = originalInstructionAddress.ToInt64() - patchMemoryAllocation.ToInt64();

        Span<byte> newCode = stackalloc byte[10];

        newCode[0] = 0x0F;
        newCode[1] = 0x1F;
        newCode[2] = 0x40;
        newCode[3] = 0x00;

        newCode[4] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(5, 4), (int)relativeReturnAddress);

        newCode[9] = 0xC3;

        if (!WriteProcessMemory(processHandle, patchMemoryAllocation, newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError("Failed to write NoSmooth patch.");
            return 0;
        }

        return patchMemoryAllocation.ToInt64() - (originalInstructionAddress.ToInt64() + 5);
    }

    private void ApplyNoSmoothPatch()
    {
        /*
            .text:00000000000DD330                 movss   dword ptr [rax], xmm0
            .text:00000000000DD334                 cmp     byte ptr [rdi+498h], 0
            .text:00000000000DD33B                 jz      short loc_DD34D
            .text:00000000000DD33D                 cmp     byte ptr [rdi+494h], 0
            .text:00000000000DD344                 jnz     short loc_DD34D
            .text:00000000000DD346                 mov     byte ptr [rdi+498h], 0
       */

        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("F3 0F 11 00 80 BF ? ? 00 00 00", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find no smooth signature.");
            return;
        }


        long jumpToNewCodeRelative = WriteNoSmoothPatch(patchMemoryAllocation, originalInstructionAddress);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 4, true))
        {
            DebugWindow.LogError("Failed to write jump to memory.");
            return;
        }
    }

    public long WriteBrightnessPatch(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress, float value)
    {
        if (!WriteValueToMemory(patchMemoryAllocation, value))
        {
            DebugWindow.LogError("Failed to write brightness value.");
            return 0;
        }

        IntPtr valueAddress = patchMemoryAllocation;

        int relativeValueAddress = (int)(valueAddress.ToInt64() - IntPtr.Add(patchMemoryAllocation, 14).ToInt64());
        long relativeReturnAddress = (originalInstructionAddress.ToInt64() + 5) - (patchMemoryAllocation.ToInt64() + 15);

        Span<byte> newCode = stackalloc byte[15];

        newCode[0] = 0xF3;
        newCode[1] = 0x44;
        newCode[2] = 0x0F;
        newCode[3] = 0x59;
        newCode[4] = 0x0D;

        BitConverter.TryWriteBytes(newCode.Slice(5, 4), relativeValueAddress);

        newCode[9] = 0xE9;

        BitConverter.TryWriteBytes(newCode.Slice(10, 4), (int)relativeReturnAddress);

        newCode[14] = 0xC3;

        if (!WriteProcessMemory(processHandle, IntPtr.Add(patchMemoryAllocation, 5), newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError("Failed to write brightness patch.");
            return 0;
        }

        return patchMemoryAllocation.ToInt64() - originalInstructionAddress.ToInt64();
    }

    public void ApplyBrightnessPatch(float value)
    {
        /*
            .text:0000000000E45D1F                 mulss   xmm9, cs:dword_2DBC390
            .text:0000000000E45D28                 lea     rdx, [rbp+57h+var_90]
            .text:0000000000E45D2C                 mov     rcx, rdi
            .text:0000000000E45D2F                 mov     qword ptr [rbp+57h+var_A0], 0
            .text:0000000000E45D37                 addss   xmm0, dword ptr [rbp+57h+var_B0]
            .text:0000000000E45D3C                 mov     dword ptr [rbp+57h+var_A0+8], 3F800000h
        */
            
        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("F3 44 0F 59 ? ? ? ? ? 48 8D ? ? 48 ? ? 48 ? 45", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find brightness signature.");
            return;
        }

        long jumpToNewCodeRelative = WriteBrightnessPatch(patchMemoryAllocation, originalInstructionAddress, value);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 4, true))
        {
            DebugWindow.LogError("Failed to write jump to memory.");
            return;
        }
    }

    public long WriteBrightnessHeight(IntPtr patchMemoryAllocation, IntPtr originalInstructionAddress)
    {
        if (!WriteVector4ToMemory(patchMemoryAllocation, new Vector4(-22.5f, -83.5f, -1000.0f, 0.0f)))
        {
            DebugWindow.LogError("Failed to write brightness height value.");
            return 0;
        }

        IntPtr valueAddress = patchMemoryAllocation;

        IntPtr addressAfterInstruction = IntPtr.Add(patchMemoryAllocation, 16 + 7); 
        int relativeValueAddress = (int)(valueAddress.ToInt64() - addressAfterInstruction.ToInt64());

        Span<byte> newCode = stackalloc byte[13];

        newCode[0] = 0x0F;
        newCode[1] = 0x10;
        newCode[2] = 0x05;

        BitConverter.TryWriteBytes(newCode.Slice(3, 4), relativeValueAddress);

        newCode[7] = 0xE9;

        long relativeReturnAddress = (originalInstructionAddress.ToInt64() + 5 + 3) - (IntPtr.Add(patchMemoryAllocation, 16 + 12).ToInt64());

        BitConverter.TryWriteBytes(newCode.Slice(8, 4), (int)relativeReturnAddress);

        newCode[12] = 0xC3;

        if (!WriteProcessMemory(processHandle, IntPtr.Add(patchMemoryAllocation, 16), newCode.ToArray(), (uint)newCode.Length, out _))
        {
            DebugWindow.LogError("Failed to write patch with movaps.");
            return 0;
        }

        return (patchMemoryAllocation.ToInt64() + 6) - (originalInstructionAddress.ToInt64() - 5);


    }

    public void ApplyBrightnessHeight()
    {
        /*
            .text:0000000000E45CE2                 movdqa  xmm0, cs:xmmword_2DBDBC0
            .text:0000000000E45CEA                 movss   xmm1, xmm4
            .text:0000000000E45CEE                 shufps  xmm1, xmm1, 0E1h
            .text:0000000000E45CF2                 movups  [rbp+57h+var_A0], xmm1
            .text:0000000000E45CF6                 movaps  [rbp+57h+var_70], xmm1
            .text:0000000000E45CFA                 movups  [rbp+57h+var_90], xmm0                                                                                               
        */

        IntPtr patchMemoryAllocation = FindUnusedSection(baseAddress - 0x10000, 1000, 10);
        if (patchMemoryAllocation == IntPtr.Zero) return;

        IntPtr originalInstructionAddress = (nint)SigScan.FindPattern("66 0F 6F 05 ? ? ? ? F3 0F 10 CC", out _);
        if (originalInstructionAddress == IntPtr.Zero)
        {
            DebugWindow.LogError("Failed to find brightness height signature.");
            return;
        }

        long jumpToNewCodeRelative = WriteBrightnessHeight(patchMemoryAllocation, originalInstructionAddress);
        if (jumpToNewCodeRelative == 0) return;

        if (!WriteJumpToMemory(originalInstructionAddress, jumpToNewCodeRelative, 3, true))
        {
            DebugWindow.LogError("Failed to write jump to memory.");
            return;
        }
    }

    public override void OnLoad()
    {
        if (baseAddress == IntPtr.Zero)
        {
            InitializeProcess();
        }

        Settings.ZoomMenu.EnableZoom.OnPressed = () =>
        {
            ApplyZoomPatch();
        };
        if (Settings.ZoomMenu.EnableZoomAtLaunch)
        {
            ApplyZoomPatch();
        }

        Settings.ZoomMenu.EnableFastZoom.OnPressed = () =>
        {
            ApplyFastZoomPatch();
            ApplyIncrementalZoomPatch();
            ApplyNoSmoothPatch();
        };
        if (Settings.ZoomMenu.EnableFastZoomAtLaunch)
        {
            ApplyIncrementalZoomPatch();
            ApplyFastZoomPatch();
        }

        Settings.QOLMenu.EnableNoFog.OnPressed = () =>
        {
            ApplyFogPatch1();
            ApplyFogPatch2();
        };
        if (Settings.QOLMenu.EnableNoFogAtLaunch)
        {
            ApplyFogPatch1();
            ApplyFogPatch2();
            if (!Settings.QOLMenu.EnableNoBlackBoxAtLaunch)
            {
                ApplyNoBlackBoxPatch(50000.0f);
            }
        }

        Settings.QOLMenu.EnableNoBlackBox.OnPressed = () =>
        {
            ApplyNoBlackBoxPatch(20000.0f);
        };

        if(Settings.QOLMenu.EnableNoBlackBoxAtLaunch)
        {
            ApplyNoBlackBoxPatch(20000.0f);
        };

        Settings.QOLMenu.EnableBrightness.OnPressed = () =>
        {
            ApplyBrightnessPatch(10000.0f);
            ApplyBrightnessHeight();
        };
        if (Settings.QOLMenu.EnableBrightnessAtLaunch)
        {
            ApplyBrightnessPatch(10000.0f);
            ApplyBrightnessHeight();
        }
    }
}