package java.lang;

public class String {
    private char[] value;
    private int offset;
    private int length;

    public char charAt(int c) {
        return value[offset + c];
    }
    @Override
    public String toString() {
        return this;
    }
    @Override
    public int hashCode() {
        int h = 0;
        for (int i = offset; i < length + offset; i++) {
            h = 31*h + value[i];
        }
        return h;
    }
    public int length() {
        return this.length;
    }
    public static String valueOf(int num) { 
        throw new NotImplementedException();
    }
    @Override
    public boolean equals(Object other) {
        if(other instanceof String) {
            String others = (String)other;
            if (others == this) {
                return true; 
            }
            else {
                if(this.length != others.length) {
                    return false;
                }
                for(int i = offset; i < this.length + offset; i++) {
                    if (this.value[i] != others.value[i]) return false;
                }
                return true;
            }
        }
        return false;
    }
    public String[] split(String str) {
        throw new NotImplementedException();
    }
}
