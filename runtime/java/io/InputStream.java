package java.io;

public abstract class InputStream {
    public abstract int available();
    public abstract int read();
    public abstract int read(byte[] bytes);
    public abstract int read(byte[] bytes, int off, int len);
    public abstract long skip(long n);
    public void close() {};
    public void mark(long mark) {}
    public boolean markSupported() {return false;}
    public void reset() {}
}

