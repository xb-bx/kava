package java.util;
import java.util.function.Predicate;
public interface Collection<E> extends Iterable<E> {
    boolean add(E e);
    boolean addAll(Collection<? extends E> c);
    void clear();
    boolean contains(Object o);
    boolean containsAll(Collection<?> c);
    boolean isEmpty();
    boolean remove(Object o);
    boolean removeAll(Collection<?> c);
    boolean retainAll(Collection<?> c);
    int size();
    Object[] toArray();
    <T> T[] toArray(T[] a);
    default boolean removeIf(Predicate<? super E> filter) {
        boolean removed = false;
        Iterator<E> iterator = iterator();
        while(iterator.hasNext()) {
            if(filter.test(iterator.next())) {
                iterator.remove();
                removed = true;
            }
        }
        return removed;
    }
}
