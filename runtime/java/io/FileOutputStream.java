package java.io;
import kava.Kava;
public class FileOutputStream extends OutputStream {
    private long fd; 
    public FileOutputStream(int fd) {
        this.fd = fd;
    }
    @Override
    public void write(int i) {
        Kava.write(this.fd, i);
    }
    @Override
    public void write(byte[] b) {
        this.write(b, 0, b.length);
    }
    @Override
    public void write(byte[] b, int off, int len) {
        Kava.write(this.fd, b, off, len);
    }
    @Override
    public void close() {
        Kava.close(this.fd);
    }
    @Override
    public void flush() {
        Kava.flush(this.fd);
    }
}
