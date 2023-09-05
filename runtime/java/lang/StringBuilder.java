package java.lang;

public class StringBuilder {
    private char[] buffer;
    private int count;
    private int capacity;
    public StringBuilder() {
        buffer = new char[32];
        capacity = 32;
        count = 0;
    }
    private void grow(int grow) {
        if(grow < capacity) {
            grow = capacity;
        }
        char[] newbuffer = new char[capacity + grow];
        for(int i = 0; i < buffer.length; i++) {
            newbuffer[i] = buffer[i];
        }
        capacity += grow;
        buffer = newbuffer;
    }
    public StringBuilder append(char c) {
        if(count == capacity) grow(-1);
        buffer[count++] = c;
        return this;
    }
    public StringBuilder append(String s) {
        if(count + s.length() >= capacity) grow(s.length());
        for(int i = 0; i < s.length(); i++) {
            buffer[count + i] = s.charAt(i);
        }
        count += s.length();
        return this;
    }
    @Override
    public String toString() {
        return new String(buffer, 0, count); 
    }

}
