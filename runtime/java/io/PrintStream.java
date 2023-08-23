package java.io;
import java.lang.NotImplementedException;
public class PrintStream {
    private FileOutputStream fs;
    public PrintStream(FileOutputStream fs) {
        this.fs = fs;
    }
    public void println(String str) {
        for(int i = 0; i < str.length(); i++) {
            fs.write(str.charAt(i));
        }
        fs.write('\n');
    }    
    public void print(String str) {
        throw new NotImplementedException(); 
    }    
    public void println() {
        throw new NotImplementedException();
    }
}

