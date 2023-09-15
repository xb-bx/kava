package java.lang;
import java.util.function.Consumer;
import java.util.Iterator;
public interface Iterable<E> {
    default void forEach(Consumer<? super E> consumer) {
        iterator().forEachRemaining(consumer);
    }
    Iterator<E> iterator();
}
