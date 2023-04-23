package dev.xdark.unsolver;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class LinuxProcessAccess implements ProcessAccess {

	@Override
	public Object openProcess(long pid) {
		return (int) pid;
	}

	@Override
	public boolean is64Bit(Object handle) {
		// TODO ?
		return System.getProperty("os.arch").contains("64");
	}

	@Override
	public boolean closeProcess(Object handle) {
		return true;
	}

	@Override
	public Object findLibJvm(Object process) {
		int pid = (int) process;
		try (BufferedReader reader = Files.newBufferedReader(Path.of("/proc/" + pid + "/maps"), StandardCharsets.UTF_8)) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.contains("libjvm.so")) {
					String path = line.substring(line.indexOf('/'));
					LinkMap linkMap = LibC.INSTANCE.dlopen(path, 1 /* RTLD_LAZY */);
					return new NativeLib(
							Long.parseLong(line.substring(0, line.indexOf('-')), 16),
							path,
							linkMap
					);
				}
			}
		} catch (IOException ignored) {
		}
		return null;
	}

	@Override
	public void closeLibJvm(Object module) {
		LibC.INSTANCE.dlclose(((NativeLib) module).linkMap.getPointer());
	}

	@Override
	public Pointer getProcAddress(Object module, String name) {
		NativeLib lib = (NativeLib) module;
		Pointer pointer = lib.addressMap.get(name);
		if (pointer == null) {
			return null;
		}
		long raw = Pointer.nativeValue(pointer);
		long ourBase = Pointer.nativeValue(lib.linkMap.getPointer());
		long dstBase = lib.base;
		return new Pointer(raw - ourBase + dstBase);
	}

	@Override
	public int readProcessMemory(Object process, Pointer base, Pointer dst, int size) {
		iovec local_iov = new iovec();
		local_iov.iov_base = dst;
		local_iov.iov_len = size;

		iovec remote_iov = new iovec();
		remote_iov.iov_base = base;
		remote_iov.iov_len = size;

		int result = LibC.INSTANCE.process_vm_readv((int) process, new iovec[]{local_iov}, 1, new iovec[]{remote_iov}, 1, 0);
		if (result == -1) {
			// Should the caller handle?...
			throw new IllegalStateException("process_vm_readv failed");
		}
		return result;
	}

	@Override
	public int writeProcessMemory(Object process, Pointer dst, Pointer src, int size) {
		iovec local_iov = new iovec();
		local_iov.iov_base = src;
		local_iov.iov_len = size;

		iovec remote_iov = new iovec();
		remote_iov.iov_base = dst;
		remote_iov.iov_len = size;

		int result = LibC.INSTANCE.process_vm_writev((int) process, new iovec[]{local_iov}, 1, new iovec[]{remote_iov}, 1, 0);
		if (result == -1) {
			// Should the caller handle?...
			throw new IllegalStateException("process_vm_writev failed");
		}
		return result;
	}

	private interface LibC extends Library {

		LibC INSTANCE = Native.load("c", LibC.class);

		LinkMap dlopen(String fileName, int flags);

		int dlclose(Pointer handle);

		int process_vm_readv(int pid, iovec[] local_iov, int liovcnt, iovec[] remote_iov, int riovcnt, long flags);

		int process_vm_writev(int pid, iovec[] local_iov, int liovcnt, iovec[] remote_iov, int riovcnt, long flags);
	}

	private static final class NativeLib {
		final long base;
		final String path;
		final LinkMap linkMap;
		final Map<String, Pointer> addressMap;

		NativeLib(long base, String path, LinkMap linkMap) {
			this.base = base;
			this.path = path;
			this.linkMap = linkMap;
			Map<String, Pointer> addressMap = new HashMap<>();
			while (linkMap != null) {
				addressMap.put(linkMap.l_name, linkMap.l_addr);
				linkMap = linkMap.l_next;
			}
			this.addressMap = addressMap;
		}
	}

	private static class LinkMap extends Structure {
		private static final class LinkMapRef extends LinkMap implements ByReference {}
		private static final List<String> ORDER = List.of("l_addr", "l_name", "l_ld", "l_next", "l_prev");
		public Pointer l_addr;
		public String l_name;
		public Pointer l_ld;
		public LinkMapRef l_next;
		public LinkMapRef l_prev;

		public LinkMap() {
		}

		public LinkMap(Pointer p) {
			super(p);
		}

		@Override
		protected List<String> getFieldOrder() {
			return ORDER;
		}
	}

	private static final class iovec extends Structure {
		private static final List<String> ORDER = List.of("iov_base", "iov_len");
		public Pointer iov_base;
		public long iov_len;

		@Override
		protected List<String> getFieldOrder() {
			return ORDER;
		}
	}
}
