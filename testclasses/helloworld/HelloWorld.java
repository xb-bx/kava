import java.io.FileInputStream;


public class HelloWorld {
    public static void main(String[] args) {
        int[][] table = new int[10][10];
        for(int i = 1; i < 10; i++) {
            for(int j = 1; j < 10; j++) {
                table[i][j] = i * j;
            }
        }
        for(int i = 1; i < 10; i++) {
            for(int j = 1; j < 10; j++) {
                System.out.print(String.valueOf(table[i][j]));
                if(table[i][j] >= 9) {
                    System.out.print(" ");
                }
                else {
                    System.out.print("  ");
                }
            }
            System.out.print("\n");
        }

    }
}
