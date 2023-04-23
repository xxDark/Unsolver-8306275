package dev.xdark.unsolver;

import com.sun.jna.Pointer;

public interface ProcessAccess {

	Object openProcess(long pid);

	boolean is64Bit(Object handle);

	boolean closeProcess(Object handle);

	Object findLibJvm(Object process);

	void closeLibJvm(Object module);

	Pointer getProcAddress(Object module, String name);

	int readProcessMemory(Object process, Pointer src, Pointer dst, int size);

	int writeProcessMemory(Object process, Pointer dst, Pointer src, int size);
}
