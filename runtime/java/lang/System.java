package java.lang;
import java.io.PrintStream;

public class System {
    public static PrintStream out;

    static {
        out = new PrintStream(kava.Kava.getStdout());
    }
}
