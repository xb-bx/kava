package java.util;

public class ArrayList<E> implements List<E> {
    private Object[] _buffer;
    private int _length, _capacity, _modCount;
    public ArrayList(int capacity) {
        _buffer = new Object[capacity];
        _length = 0;
        _capacity = capacity;
    }
    public ArrayList() {
        this(4);
    }
    public ArrayList(Collection<? extends E> c) {
        this(c.size());
        for(E elem : c) {
            this.add(elem);
        }
    }
    public E get(int index) {
        if(index < 0 || index >= _length)
            throw new IndexOutOfBoundsException();
        E elem = (E)_buffer[index];
        return elem;
    }
    public E set(int index, E elem) {
        if(index < 0 || index >= _length)
            throw new IndexOutOfBoundsException();
        _modCount++;
        E prev = (E)_buffer[index];
        _buffer[index] = elem;
        return prev;
    }
    public E remove(int index) {
        if(index < 0 || index >= _length)
            throw new IndexOutOfBoundsException();
        E prev = (E)_buffer[index];
        for(int i = index + 1; i < _length; i++) {
            _buffer[i - 1] = _buffer[i];
        } 
        _modCount++;
        return prev;
    }
    public boolean addAll(Collection<? extends E> elems) {
        return addAll(_length, elems);
    }
    public boolean addAll(int index, Collection<? extends E> elems) {
        int i = 0;
        boolean res = false;
        for(E elem : elems) {
            res = true;
            this.add(index + i, elem);
        }
        return res;
    }
    public void add(int index, E elem) {
        if(index < 0 || index > _length)
            throw new IndexOutOfBoundsException();
        if(index == _length) add(elem);
        else throw new NotImplementedException();
    }
    public int size() {
        return _length;
    }
    public boolean add(E elem) {
        _modCount++;
        if(_length < _capacity) {
            _buffer[_length++] = elem;
            return true;
        }
        else {
            Object[] newbuff = new Object[_capacity * 2];
            for(int i = 0; i < _capacity; i++)
                newbuff[i] = _buffer[i];
            _buffer = newbuff;
            _capacity *= 2;
            _buffer[_length++] = elem;
            return true;
        }
//         return true;
    }
    public int indexOf(Object elem) {
        throw new NotImplementedException();
    }
    public int lastIndexOf(Object elem) {
        throw new NotImplementedException();
    }
    public List<E> subList(int from, int to) {
        throw new NotImplementedException();
    } 
    public <T> T[] toArray(T[] arr) {
        throw new NotImplementedException();
    }
    public Object[] toArray() {
        Object[] res = new Object[size()];
        for(int i = 0; i < size(); i++) 
            res[i] = _buffer[i];
        return res;
    }
    public boolean retainAll(Collection<?> c) {
        throw new NotImplementedException();
    }
    public boolean removeAll(Collection<?> c) {
        throw new NotImplementedException();
    }
    public boolean containsAll(Collection<?> c) {
        throw new NotImplementedException();
    }
    public boolean contains(Object e) {
        return indexOf(e) != -1; 
    }
    public boolean remove(Object e) {
        int index = indexOf(e);
        if(index == -1) return false;
        remove(index);
        return true;
    }
    public boolean isEmpty() {
        return _length == 0;
    }
    public void clear() {
        _modCount++;
        _length = 0;
    }
    public Iterator<E> iterator() {
        return new ArrayIterator();
    }
    private class ArrayIterator implements Iterator<E> {
        private int _cursor;
        private int _expectedModCount;

        public ArrayIterator() {
            _expectedModCount = _modCount;
        }
        public boolean hasNext() {
            return _cursor < size();
        }
        public E next() {
            if(hasNext()) {
                if(_modCount != _expectedModCount) {
                System.out.println(String.valueOf(_modCount) + " " + String.valueOf(_expectedModCount));
                    throw new ConcurrentModificationException();
                }
                return (E)_buffer[_cursor++];
            }
            else {
                throw new NoSuchElementException();
            }
        }
    }
}
