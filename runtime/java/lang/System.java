package java.lang;
import java.io.PrintStream;
import java.io.InputStream;

public class System {
    public static PrintStream out;
    public static InputStream in;

    static {
        out = new PrintStream(kava.Kava.getStdout());
        in = kava.Kava.getStdin();
    }
}
