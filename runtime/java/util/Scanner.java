package java.util;
import java.io.InputStream;

public class Scanner {
    private final InputStream stream;
    public Scanner(InputStream stream) {
        this.stream = stream;
    }
    public String nextLine() {
        StringBuilder sb = new StringBuilder();
        char r = 0;
        do {
            if(r != 0) sb.append(r);
            r = (char)stream.read();
            if(r == '\r') r = (char)stream.read();
        } while(r != '\n' && r != '\r');
        return sb.toString();
    }
}
