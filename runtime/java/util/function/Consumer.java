package java.util.function;
import java.lang.NotImplementedException;

public interface Consumer<T> {
    void accept(T obj);

    default Consumer<T> andThen(Consumer<? super T> after) {
        throw new NotImplementedException();
    }
}
