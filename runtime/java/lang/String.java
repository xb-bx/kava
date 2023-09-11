package java.lang;

public class String implements Comparable<String> {
    private char[] value;
    private int offset;
    private int length;

    public String(char[] buf, int off, int len) {
        this.value = buf;
        this.offset = off;
        this.length = len;
    }
    public String() {
        this.value = new char[0];
        this.offset = 0;
        this.length = 0;
        
    }
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
    public static String valueOf(char c) {
        return new String(new char[] {c}, 0, 1);
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
        if(str.length() == 1) {
            return splitByChar(str.charAt(0));
        }
        throw new NotImplementedException();
    }
    private int countChars(char c) {
        int res = 0;
        for(int i = 0; i < length; i++) {
            if(charAt(i) == c) res++;
        }
        return res;
    }
    private String[] splitByChar(char c) {
        String[] res = new String[countChars(c) + 1];
        int resi = 0;
        if(res.length == 0) {
            res[0] = this;
            return res;
        }
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < length; i++) {
            if(charAt(i) != c) {
                sb.append(charAt(i));
            } else {
                res[resi++] = sb.toString();
                sb = new StringBuilder();
            }
        }
        if(sb.length() > 0) {
            res[resi] = sb.toString();
        }
        return res;
    }
    public int compareTo(String other) {
        if(equals(other)) return 0;
        if(length != other.length) return length - other.length;
        for(int i = 0; i < length; i++) {
            if(charAt(i) != other.charAt(i)) {
                return charAt(i) - other.charAt(i);
            }
        }
        return -1;
    }
}
