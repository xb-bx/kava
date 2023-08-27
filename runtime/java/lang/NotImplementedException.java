package java.lang;
public class NotImplementedException extends RuntimeException {
    public final String message;
    public NotImplementedException(String msg) {
        message = msg;
    }
    public NotImplementedException() {
        message = null;
    }
    @Override
    public String toString() {
        return message == null ? "java/lang/NotImplementedException" : message;
    }
}
