package dev.xdark.unsolver;

import com.sun.jna.Native;

final class Util {

	static <T> T checkNotNull(T any, String msg) {
		if (any == null) {
			throw new IllegalStateException(msg + " " + Native.getLastError());
		}
		return any;
	}

	static void checkTrue(boolean condition, String msg) {
		if (!condition) {
			throw new IllegalStateException(msg + " " + Native.getLastError());
		}
	}
}
