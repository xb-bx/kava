package java.lang;

public class Throwable extends Object {
    public final String message;
    public Throwable() {
        message = null;
    }
    public Throwable(String msg) {
        message = msg;
    }
    @Override
    public String toString() {
        return message == null ? super.toString() : message;
    }

}
