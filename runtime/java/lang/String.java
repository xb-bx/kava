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
        if(num == 0) return "0";
        char[] buf = new char[16];
        int i = 15;
        boolean isneg = num < 0;
        num = num < 0 ? -num : num;
        while(num != 0) {
            int n = num % 10;
            buf[i--] = (char)(n + '0');
            num /= 10;
        }
        if(isneg) {
            buf[i--] = '-';
        }
        
        String res = new String();
        res.value = buf;
        res.offset = i + 1;
        res.length = 16 - i - 1;
        return res;
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
