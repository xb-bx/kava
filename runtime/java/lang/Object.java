package java.lang;

public class Object {

    public String toString() {
        return kava.Kava.objectToString(this);
    }
    public int hashCode() {
        return kava.Kava.objectHashCode(this);
    }
    public boolean equals(Object other) {
        return this == other;
    }
    
}
