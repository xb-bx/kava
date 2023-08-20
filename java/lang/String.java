package java.lang;

public class String {
    private char[] data;
    private int offset;
    private int length;

    public char charAt(int c) {
        return data[offset + c];
    }
    @Override
    public String toString() {
        return this;
    }
    @Override
    public int hashCode() {
        int sum = 0;
        for(int i = offset; i < length; i++) {
            sum += data[i] * Math.pow(31, length - i - offset - 1);
        }
        return sum;
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
                for(int i = 0; i < this.length; i++) {
                    if (this.data[i] != others.data[i]) return false;
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
