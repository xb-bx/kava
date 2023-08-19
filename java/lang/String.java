package java.lang;

public class String {
    private char[] data;
    private int offset;
    private int length;

    @Override
    public String toString() {
        return this;
    }
    @Override
    public int hashCode() {
        return data[0];
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
}
