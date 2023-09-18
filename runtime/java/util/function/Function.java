package java.util.function;
import java.lang.NotImplementedException;
public interface Function<T, R> {
    default <V> Function<R, V> andThen(Function<? super R, ? extends V> after) {
        throw new NotImplementedException();
    }
    R apply(T t);
    default <V> Function<V,R> compose(Function<? super V,? extends T> before) {
        throw new NotImplementedException();
    }
    static <T> Function<T,T> identity() {
        throw new NotImplementedException();
    }

}
