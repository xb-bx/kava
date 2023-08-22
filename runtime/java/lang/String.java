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
    public int pow(int x, int n) {
        while(n > 0) {
            x *= n;
        }
        return x;
    }
    @Override
    public int hashCode() {
        System.out.println("Hello");
        int sum = 0;
        for(int i = offset; i < length; i++) {
            sum += value[i] * (pow(31, length - i - offset - 1));
        }
        System.out.println("Bye");
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
