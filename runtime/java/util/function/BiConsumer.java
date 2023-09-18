package java.util.function;
import java.lang.NotImplementedException;

public interface BiConsumer<T, U> {
    void accept(T obj, U obj1);

    default BiConsumer<T, U> andThen(BiConsumer<? super T, ? super U> after) {
        throw new NotImplementedException();
    }
}
