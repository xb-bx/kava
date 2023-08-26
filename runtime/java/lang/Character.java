package java.lang;

public class Character {
    public static boolean isDigit(char c) {
        System.out.println(String.valueOf(c));
        return (int)c >= (int)'0' && (int)c <= (int)'9';
    }
}
