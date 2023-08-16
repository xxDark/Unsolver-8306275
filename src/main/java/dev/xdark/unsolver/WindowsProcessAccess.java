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
		int pointerSize = Native.POINTER_SIZE;
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
				WinDef.HMODULE lib = Kernel32.INSTANCE.LoadLibraryEx(moduleName, null, 0x00000001 /* DONT_RESOLVE_DLL_REFERENCES */);
				Util.checkNotNull(lib, "LoadLibraryEx");
				return new Lib(lib, moduleHandle);
			}
		}
		return null;
	}

	@Override
	public void closeLibJvm(Object module) {
		Kernel32.INSTANCE.CloseHandle(((Lib) module).ourHandle);
	}

	@Override
	public Pointer getProcAddress(Object module, String name) {
		Lib lib = (Lib) module;
		WinDef.LPVOID address = Kernel32Ext.INSTANCE.GetProcAddress(lib.ourHandle, name);
		if (address == null) {
			return null;
		}
		long raw = Pointer.nativeValue(address.getPointer());
		long ourBase = Pointer.nativeValue(lib.ourHandle.getPointer());
		long dstBase = Pointer.nativeValue(lib.theirHandle.getPointer());
		long result = raw - ourBase + dstBase;
		return new Pointer(result);
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
		Kernel32Ext INSTANCE = Native.load("kernel32",
				Kernel32Ext.class, W32APIOptions.ASCII_OPTIONS);

		WinDef.LPVOID GetProcAddress(WinDef.HMODULE hModule, String lpProcName);
	}

	private static final class Lib {
		final WinDef.HMODULE ourHandle;
		final WinDef.HMODULE theirHandle;

		Lib(WinDef.HMODULE ourHandle, WinDef.HMODULE theirHandle) {
			this.ourHandle = ourHandle;
			this.theirHandle = theirHandle;
		}
	}
}
