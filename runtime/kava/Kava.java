package kava;
import java.io.FileOutputStream; 

public class Kava {
    public static native FileOutputStream getStdout(); 
    public static native void write(long handle, byte[] bytes, int off, int len);
    public static native void write(long handle, int b);
    public static native void close(long handle);
    public static native void flush(long handle);

}
