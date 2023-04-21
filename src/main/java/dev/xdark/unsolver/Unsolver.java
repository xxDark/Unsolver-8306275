package dev.xdark.unsolver;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import com.sun.jna.win32.W32APIOptions;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Unsolver {

	public static void enableDynamicAgentLoading(long pid) {
		WinNT.HANDLE targetProcess = checkNotNull(Kernel32.INSTANCE.OpenProcess(
				0x0008 | 0x0010 | 0x0020,
				false,
				(int) pid
		), "OpenProcess");
		try {
			WinNT.HANDLE thisProcess = Kernel32.INSTANCE.GetCurrentProcess();
			IntByReference bytesRead = new IntByReference();
			IntByReference ref = bytesRead;
			checkTrue(Kernel32.INSTANCE.IsWow64Process(thisProcess, ref), "IsWow64Process this");
			int pointerSize = ref.getValue() == 1 ? 4 : 8;
			checkTrue(Kernel32.INSTANCE.IsWow64Process(targetProcess, ref), "IsWow64Process target");
			boolean isTargetProcess64bit = ref.getValue() == 0;
			int targetSize = isTargetProcess64bit ? 8 : 4;
			WinDef.HMODULE[] modules = new WinDef.HMODULE[512];
			checkTrue(Psapi.INSTANCE.EnumProcessModules(
					targetProcess,
					modules,
					512 * pointerSize,
					ref
			), "EnumProcessModules");
			char[] pathBuf = new char[260];
			for (int i = 0, j = ref.getValue() / pointerSize; i < j; i++) {
				WinDef.HMODULE moduleHandle = modules[i];
				int len = Psapi.INSTANCE.GetModuleFileNameExW(targetProcess, moduleHandle, pathBuf, 260);
				checkTrue(len != 0, "GetModuleFileNameExA");
				String moduleName = new String(pathBuf, 0, len);
				if (moduleName.contains("jvm.dll")) {
					WinSymbolLookup lookup = new WinSymbolLookup(moduleHandle, isTargetProcess64bit);

					Map<String, Map<String, Field>> map = new HashMap<>();
					{
						long entry = lookup.getSymbol("gHotSpotVMStructs");
						long typeNameOffset = lookup.getSymbol("gHotSpotVMStructEntryTypeNameOffset");
						long fieldNameOffset = lookup.getSymbol("gHotSpotVMStructEntryFieldNameOffset");
						long stride = lookup.getSymbol("gHotSpotVMStructEntryArrayStride");
						long isStaticOffset = lookup.getSymbol("gHotSpotVMStructEntryIsStaticOffset");
						long addressOffset = lookup.getSymbol("gHotSpotVMStructEntryAddressOffset");
						long offsetOffset = lookup.getSymbol("gHotSpotVMStructEntryOffsetOffset");
						WinHotSpotTraverse traverse = new WinHotSpotTraverse(
								targetProcess,
								targetSize,
								typeNameOffset,
								fieldNameOffset,
								isStaticOffset,
								addressOffset,
								offsetOffset
						);
						while (true) {
							String fieldName = traverse.getFieldName(entry);
							if (fieldName == null) {
								break;
							}
							String typeName = traverse.getTypeName(entry);
							boolean isStatic = traverse.isStatic(entry);
							long offset = isStatic ? traverse.getAddress(entry) : traverse.getOffset(entry);
							map.computeIfAbsent(typeName, __ -> new HashMap<>())
									.put(fieldName, new Field(offset, isStatic));
							entry += stride;
						}
					}
					String flagTypeName = "Flag";
					Map<String, Field> type = map.get(flagTypeName);
					if (type == null) {
						flagTypeName = "JVMFlag";
						type = map.get(flagTypeName);
					}
					checkNotNull(type, "no JVMFlag in target process");
					{
						long entry = lookup.getSymbol("gHotSpotVMTypes");
						long typeNameOffset = lookup.getSymbol("gHotSpotVMTypeEntryTypeNameOffset");
						long sizeOffset = lookup.getSymbol("gHotSpotVMTypeEntrySizeOffset");
						long stride = lookup.getSymbol("gHotSpotVMTypeEntryArrayStride");
						WinHotSpotTraverse traverse = new WinHotSpotTraverse(
								targetProcess,
								targetSize,
								typeNameOffset,
								0L,
								0L,
								0L,
								sizeOffset
						);
						while (true) {
							String typeName = traverse.getTypeName(entry);
							if (typeName == null) {
								break;
							}
							if (flagTypeName.equals(typeName)) {
								int size = traverse.getOffset(entry);
								long numFlags = type.get("numFlags").offset;
								Memory memory = new Memory(1024);
								checkTrue(
										Kernel32.INSTANCE.ReadProcessMemory(targetProcess, Pointer.createConstant(numFlags), memory, 4, bytesRead),
										"ReadProcessMemory numFlags"
								);
								int flagCount = memory.getInt(0);
								checkTrue(
										Kernel32.INSTANCE.ReadProcessMemory(targetProcess, Pointer.createConstant(type.get("flags").offset), memory, targetSize, bytesRead),
										"ReadProcessMemory flags"
								);
								Pointer baseFlagAddress = checkNotNull(readPointer(memory, targetSize), "base flag pointer");
								long _name = type.get("_name").offset;
								long _addr = type.get("_addr").offset;

								for (int k = 0; k < flagCount - 1; k++) {
									Pointer flagAddress = baseFlagAddress.share((long) k * size);
									checkTrue(
											Kernel32.INSTANCE.ReadProcessMemory(targetProcess, flagAddress.share(_name), memory, 1024, bytesRead),
											"ReadProcessMemory name"
									);
									String flagName = readStringA(readPointer(memory, targetSize), bytesRead.getValue());
									if ("EnableDynamicAgentLoading".equals(flagName)) {
										checkTrue(
												Kernel32.INSTANCE.ReadProcessMemory(targetProcess, flagAddress.share(_addr), memory, targetSize, bytesRead),
												"ReadProcessMemory address"
										);
										Pointer valueAddress = readPointer(memory, targetSize);
										memory.setByte(0L, (byte) 1);
										checkTrue(
												Kernel32.INSTANCE.WriteProcessMemory(targetProcess, valueAddress, memory, 1, bytesRead),
												"WriteProcessMemory"
										);
										return;
									}
								}
							}
							entry += stride;
						}
					}
					break;
				}
			}
		} finally {
			Kernel32.INSTANCE.CloseHandle(targetProcess);
		}
		throw new IllegalStateException("Could not change EnableDynamicAgentLoading flag");
	}

	static <T> T checkNotNull(T any, String msg) {
		if (any == null) {
			throw new IllegalStateException(msg);
		}
		return any;
	}

	static void checkTrue(boolean condition, String msg) {
		if (!condition) {
			throw new IllegalStateException(msg);
		}
	}

	private static Pointer readPointer(Pointer from, int ptrSize) {
		long raw = ptrSize == 8 ? from.getLong(0) : from.getInt(0);
		if (raw == 0L) return null;
		return new Pointer(raw);
	}

	private static String readStringA(Pointer pointer, int size) {
		char[] buf = new char[32];
		int i;
		for (i = 0; i < size; i++) {
			byte b = pointer.getByte(i);
			if (b == 0) {
				break;
			}
			if (i == buf.length) {
				buf = Arrays.copyOf(buf, i + 16);
			}
			buf[i] = (char) b;
		}
		return new String(buf, 0, i);
	}

	private static String readStringA(Pointer pointer, IntByReference size) {
		return readStringA(pointer, size.getValue());
	}

	private static final class Field {
		final long offset;
		final boolean isStatic;

		Field(long offset, boolean isStatic) {
			this.offset = offset;
			this.isStatic = isStatic;
		}
	}

	private static final class WinHotSpotTraverse {
		final WinNT.HANDLE process;
		final int pointerSize;
		final long typeNameOffset;
		final long fieldNameOffset;
		final long isStaticOffset;
		final long addressOffset;
		final long offsetOffset;
		final Memory memory;

		WinHotSpotTraverse(WinNT.HANDLE process, int pointerSize, long typeNameOffset, long fieldNameOffset, long isStaticOffset, long addressOffset, long offsetOffset) {
			this.process = process;
			this.pointerSize = pointerSize;
			this.typeNameOffset = typeNameOffset;
			this.fieldNameOffset = fieldNameOffset;
			this.isStaticOffset = isStaticOffset;
			this.addressOffset = addressOffset;
			this.offsetOffset = offsetOffset;
			memory = new Memory(1024);
		}

		String getTypeName(long entry) {
			return getStringAt(entry, typeNameOffset);
		}

		String getFieldName(long entry) {
			return getStringAt(entry, fieldNameOffset);
		}

		boolean isStatic(long entry) {
			IntByReference bytesRead = new IntByReference();
			checkTrue(
					Kernel32.INSTANCE.ReadProcessMemory(process, Pointer.createConstant(entry + isStaticOffset), memory, 4, bytesRead),
					"ReadProcessMemory address"
			);
			return memory.getInt(0) == 1;
		}

		int getOffset(long entry) {
			IntByReference bytesRead = new IntByReference();
			checkTrue(
					Kernel32.INSTANCE.ReadProcessMemory(process, Pointer.createConstant(entry + offsetOffset), memory, 4, bytesRead),
					"ReadProcessMemory address"
			);
			return memory.getInt(0);
		}

		long getAddress(long entry) {
			IntByReference bytesRead = new IntByReference();
			checkTrue(
					Kernel32.INSTANCE.ReadProcessMemory(process, Pointer.createConstant(entry + addressOffset), memory, pointerSize, bytesRead),
					"ReadProcessMemory address"
			);
			return pointerSize == 8 ? memory.getLong(0) : memory.getInt(0);
		}

		private String getStringAt(long entry, long offset) {
			IntByReference bytesRead = new IntByReference();
			checkTrue(
					Kernel32.INSTANCE.ReadProcessMemory(process, Pointer.createConstant(entry + offset), memory, pointerSize, bytesRead),
					"ReadProcessMemory address"
			);
			Pointer ptr = readPointer(memory, pointerSize);
			if (ptr == null) {
				return null;
			}
			checkTrue(
					Kernel32.INSTANCE.ReadProcessMemory(process, ptr, memory, 1024, bytesRead),
					"ReadProcessMemory content"
			);
			return readStringA(memory, bytesRead);
		}
	}

	private static final class WinSymbolLookup {

		final WinDef.HMODULE module;
		final boolean is64bit;

		WinSymbolLookup(WinDef.HMODULE module, boolean is64bit) {
			this.module = module;
			this.is64bit = is64bit;
		}

		long getSymbol(String name) {
			WinDef.LPVOID address = checkNotNull(
					Kernel32Ext.INSTANCE.GetProcAddress(module, name),
					name
			);
			Pointer ptr = address.getPointer();
			return is64bit ? ptr.getLong(0) : ptr.getInt(0);
		}
	}

	public interface Kernel32Ext extends StdCallLibrary {
		Kernel32Ext INSTANCE = Native.loadLibrary("kernel32",
				Kernel32Ext.class, W32APIOptions.ASCII_OPTIONS);

		WinDef.LPVOID GetProcAddress(WinDef.HMODULE hModule, String lpProcName);
	}
}
