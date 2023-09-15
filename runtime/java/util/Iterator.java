package java.util;
import java.util.function.Consumer;
public interface Iterator<E> {
    default void forEachRemaining(Consumer<? super E> consumer) {
        while(hasNext()) {
            consumer.accept(next());
        }
    }
    default void remove() {
        throw new UnsupportedOperationException();
    }
    boolean hasNext();
    E next();

}
