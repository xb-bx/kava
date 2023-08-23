package java.io;
import java.lang.NotImplementedException;

public class FileInputStream extends InputStream {
    private long fd;
    public FileInputStream(long fd) {
        this.fd = fd;
    }
    public int available() {
        return kava.Kava.getAvailableBytes(fd);
    }
    public int read() {
        return kava.Kava.read(fd);
    }
    public int read(byte[] bytes)  { throw new NotImplementedException(); }
    public int read(byte[] bytes, int off, int len)  { throw new NotImplementedException(); }
    public long skip(long n)  { throw new NotImplementedException(); }
    public void close() { throw new NotImplementedException(); }
    public void mark(long mark)  { throw new NotImplementedException(); }
    public boolean markSupported()  { throw new NotImplementedException(); }
    public void reset()  { throw new NotImplementedException(); }
}

