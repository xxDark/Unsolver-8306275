package dev.xdark.unsolver;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class Unsolver {
	private Unsolver() {
	}

	public static void enableDynamicAgentLoading(long pid) {
		ProcessAccess access;
		if (System.getProperty("os.name").toLowerCase(Locale.US).contains("win")) {
			access = new WindowsProcessAccess();
		} else {
			access = new LinuxProcessAccess();
		}
		Object targetProcess = access.openProcess(pid);
		Util.checkNotNull(targetProcess, "openProcess failed");
		Object jvm = null;
		try {
			jvm = Util.checkNotNull(access.findLibJvm(targetProcess), "libjvm");
			boolean is64bit = access.is64Bit(targetProcess);
			int targetSize = is64bit ? 8 : 4;
			SymbolLookup lookup = new SymbolLookup(access, targetProcess, jvm, is64bit);

			Map<String, Map<String, Field>> map = new HashMap<>();
			{
				long entry = lookup.getSymbol("gHotSpotVMStructs");
				long typeNameOffset = lookup.getSymbol("gHotSpotVMStructEntryTypeNameOffset");
				long fieldNameOffset = lookup.getSymbol("gHotSpotVMStructEntryFieldNameOffset");
				long stride = lookup.getSymbol("gHotSpotVMStructEntryArrayStride");
				long isStaticOffset = lookup.getSymbol("gHotSpotVMStructEntryIsStaticOffset");
				long addressOffset = lookup.getSymbol("gHotSpotVMStructEntryAddressOffset");
				long offsetOffset = lookup.getSymbol("gHotSpotVMStructEntryOffsetOffset");
				HotSpotTraverse traverse = new HotSpotTraverse(
						access,
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
			Util.checkNotNull(type, "no JVMFlag in target process");
			{
				long entry = lookup.getSymbol("gHotSpotVMTypes");
				long typeNameOffset = lookup.getSymbol("gHotSpotVMTypeEntryTypeNameOffset");
				long sizeOffset = lookup.getSymbol("gHotSpotVMTypeEntrySizeOffset");
				long stride = lookup.getSymbol("gHotSpotVMTypeEntryArrayStride");
				HotSpotTraverse traverse = new HotSpotTraverse(
						access,
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
						access.readProcessMemory(targetProcess, Pointer.createConstant(numFlags), memory, 4);
						int flagCount = memory.getInt(0);
						access.readProcessMemory(targetProcess, Pointer.createConstant(type.get("flags").offset), memory, targetSize);
						Pointer baseFlagAddress = Util.checkNotNull(readPointer(memory, targetSize), "base flag pointer");
						long _name = type.get("_name").offset;
						long _addr = type.get("_addr").offset;

						for (int k = 0; k < flagCount - 1; k++) {
							Pointer flagAddress = baseFlagAddress.share((long) k * size);
							access.readProcessMemory(targetProcess, flagAddress.share(_name), memory, targetSize);
							Pointer pointer = readPointer(memory, targetSize);
							access.readProcessMemory(targetProcess, pointer, memory, 1024);
							String flagName = readStringA(memory, 1024);
							if ("EnableDynamicAgentLoading".equals(flagName)) {
								access.readProcessMemory(targetProcess, flagAddress.share(_addr), memory, targetSize);
								Pointer valueAddress = readPointer(memory, targetSize);
								memory.setByte(0L, (byte) 1);
								access.writeProcessMemory(targetProcess, valueAddress, memory, 1);
								return;
							}
						}
					}
					entry += stride;
				}
			}
		} finally {
			if (jvm != null) {
				access.closeLibJvm(jvm);
			}
			if (targetProcess != null) {
				access.closeProcess(targetProcess);
			}
		}
		throw new IllegalStateException("Could not change EnableDynamicAgentLoading flag");
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

	private static final class Field {
		final long offset;
		final boolean isStatic;

		Field(long offset, boolean isStatic) {
			this.offset = offset;
			this.isStatic = isStatic;
		}
	}

	private static final class HotSpotTraverse {
		final ProcessAccess access;
		final Object process;
		final int pointerSize;
		final long typeNameOffset;
		final long fieldNameOffset;
		final long isStaticOffset;
		final long addressOffset;
		final long offsetOffset;
		final Memory memory;

		HotSpotTraverse(ProcessAccess access, Object process, int pointerSize, long typeNameOffset, long fieldNameOffset, long isStaticOffset, long addressOffset, long offsetOffset) {
			this.access = access;
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
			access.readProcessMemory(process, Pointer.createConstant(entry + isStaticOffset), memory, 4);
			return memory.getInt(0) == 1;
		}

		int getOffset(long entry) {
			access.readProcessMemory(process, Pointer.createConstant(entry + offsetOffset), memory, 4);
			return memory.getInt(0);
		}

		long getAddress(long entry) {
			access.readProcessMemory(process, Pointer.createConstant(entry + addressOffset), memory, pointerSize);
			return pointerSize == 8 ? memory.getLong(0) : memory.getInt(0);
		}

		private String getStringAt(long entry, long offset) {
			access.readProcessMemory(process, Pointer.createConstant(entry + offset), memory, pointerSize);
			Pointer ptr = readPointer(memory, pointerSize);
			if (ptr == null) {
				return null;
			}
			int bytesRead = access.readProcessMemory(process, ptr, memory, 1024);
			return readStringA(memory, bytesRead);
		}
	}

	private static final class SymbolLookup {

		final ProcessAccess access;
		final Object module;
		final Object process;
		final boolean is64bit;
		private final Memory tmp;

		SymbolLookup(ProcessAccess access, Object process, Object module, boolean is64bit) {
			this.access = access;
			this.process = process;
			this.module = module;
			this.is64bit = is64bit;
			tmp = new Memory(8);
		}

		long getSymbol(String name) {
			Pointer ptr = Util.checkNotNull(access.getProcAddress(module, name), name);
			Memory tmp = this.tmp;
			access.readProcessMemory(process, ptr, tmp, is64bit ? 8 : 4);
			return is64bit ? tmp.getLong(0) : tmp.getInt(0);
		}
	}
}
