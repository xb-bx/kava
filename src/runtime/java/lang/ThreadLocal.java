package java.lang;

public class ThreadLocal<T> {
    private T value;

    public void set(T newvalue) {
        value = newvalue;
    }
    public T get() { return value; }
}
