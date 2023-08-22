package java.io;

public abstract class OutputStream {
    public abstract void close();
    public abstract void flush();
    public abstract void write(int i);
    public abstract void write(byte[] b);
    public abstract void write(byte[] b, int off, int len);
}
