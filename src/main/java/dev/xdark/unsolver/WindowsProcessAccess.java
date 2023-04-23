package dev.xdark.unsolver;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

final class WindowsProcessAccess implements ProcessAccess {

	@Override
	public Object openProcess(long pid) {
		return Util.checkNotNull(Kernel32.INSTANCE.OpenProcess(
				0x0008 | 0x0010 | 0x0020,
				false,
				(int) pid
		), "OpenProcess");
	}

	@Override
	public boolean is64Bit(Object handle) {
		IntByReference ref = new IntByReference();
		Util.checkTrue(Kernel32.INSTANCE.IsWow64Process((WinNT.HANDLE) handle, ref), "IsWow64Process");
		return ref.getValue() == 0;
	}

	@Override
	public boolean closeProcess(Object handle) {
		return Kernel32.INSTANCE.CloseHandle((WinNT.HANDLE) handle);
	}

	@Override
	public Object findLibJvm(Object process) {
		int pointerSize = is64Bit(Kernel32.INSTANCE.GetCurrentProcess()) ? 8 : 4;
		WinDef.HMODULE[] modules = new WinDef.HMODULE[512];
		IntByReference ref = new IntByReference();
		Util.checkTrue(Psapi.INSTANCE.EnumProcessModules(
				(WinNT.HANDLE) process,
				modules,
				512 * pointerSize,
				ref
		), "EnumProcessModules");
		char[] pathBuf = new char[260];
		for (int i = 0, j = ref.getValue() / pointerSize; i < j; i++) {
			WinDef.HMODULE moduleHandle = modules[i];
			int len = Psapi.INSTANCE.GetModuleFileNameExW((WinNT.HANDLE) process, moduleHandle, pathBuf, 260);
			Util.checkTrue(len != 0, "GetModuleFileNameExA");
			String moduleName = new String(pathBuf, 0, len);
			if (moduleName.contains("jvm.dll")) {
				return moduleHandle;
			}
		}
		return null;
	}

	@Override
	public void closeLibJvm(Object module) {
		// Do nothing
	}

	@Override
	public Pointer getProcAddress(Object module, String name) {
		WinDef.LPVOID address = Kernel32Ext.INSTANCE.GetProcAddress((WinDef.HMODULE) module, name);
		return address == null ? null : address.getPointer();
	}

	@Override
	public int readProcessMemory(Object process, Pointer src, Pointer dst, int size) {
		IntByReference read = new IntByReference();
		Util.checkTrue(
				Kernel32.INSTANCE.ReadProcessMemory((WinNT.HANDLE) process, src, dst, size, read),
				"ReadProcessMemory"
		);
		return read.getValue();
	}

	@Override
	public int writeProcessMemory(Object process, Pointer dst, Pointer src, int size) {
		IntByReference written = new IntByReference();
		Util.checkTrue(
				Kernel32.INSTANCE.WriteProcessMemory((WinNT.HANDLE) process, dst, src, size, written),
				"WriteProcessMemory"
		);
		return written.getValue();
	}

	public interface Kernel32Ext extends StdCallLibrary {
		Kernel32Ext INSTANCE = Native.loadLibrary("kernel32",
				Kernel32Ext.class, W32APIOptions.ASCII_OPTIONS);

		WinDef.LPVOID GetProcAddress(WinDef.HMODULE hModule, String lpProcName);
	}
}
