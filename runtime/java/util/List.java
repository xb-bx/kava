package java.util;
import java.util.Collection;
import java.lang.Iterable;
import java.util.function.UnaryOperator;

public interface List<E> extends Collection<E> {
    boolean add(E elem);
    void add(int index, E elem);
    boolean addAll(int index, Collection<? extends E> elem);
    E get(int index);
    int indexOf(Object elem);
    int lastIndexOf(Object elem);
    E remove(int index);
    default void replaceAll(UnaryOperator<E> op) {
        throw new NotImplementedException();
    }
    E set(int index, E elem);
    List<E> subList(int from, int to);


}
