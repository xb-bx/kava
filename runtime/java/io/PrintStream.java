package java.io;
public class PrintStream {
    private FileOutputStream fs;
    public PrintStream(FileOutputStream fs) {
        this.fs = fs;
    }
    public void println(String str) {
        this.print(str);
        fs.write('\n');
    }    
    public void print(String str) {
        for(int i = 0; i < str.length(); i++) {
            fs.write(str.charAt(i));
        }
    }    
    public void print(char c) {
        fs.write(c);
    }    
    public void println() {
        fs.write('\n');
    }
}

