package java.lang;

public class Integer {
    public static final int MAX_VALUE = 0x7FFFFFFF;
    public static int parseInt(String s) {
        long res = 0;
        int mul = 1;
        for(int i = s.length() - 1; i >= 0; i--) {
            int c = s.charAt(i); 
            if(c == '-' && i == 0) {
                res = -res;
                return (int)res;
            }
            else if(c >= '0' && c <= '9') {
                res += (c - '0') * mul;
                mul *= 10;
                if(res > MAX_VALUE) {
                    throw new NumberFormatException();
                }
            }
            else {
                throw new NumberFormatException();
            }
        }
        return (int)res;
    }
}
