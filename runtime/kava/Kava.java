package kava;
import java.io.FileOutputStream; 
import java.io.FileInputStream; 

public class Kava {
    public static native FileOutputStream getStdout(); 
    public static native FileInputStream getStdin(); 
    public static native void write(long handle, byte[] bytes, int off, int len);
    public static native void write(long handle, int b);
    public static native void close(long handle);
    public static native void flush(long handle);
    public static native int getAvailableBytes(long handle);
    public static native int read(long handle);
    public static native int read(long handle, byte[] bytes, int off, int len);
    public static native String objectToString(Object obj);
    public static native int objectHashCode(Object obj);
    public static native double randomDouble();
}
