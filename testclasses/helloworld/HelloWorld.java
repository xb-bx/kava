import java.io.FileInputStream;


public class HelloWorld {
    public static void main(String[] args) {
//         if (args.length > 0) {
//             for(String arg: args) {
//                 System.out.println(arg);
//             }
//         }
//         else {
//             System.out.println("No arguments supplied");
//         }
        while(System.in.available() > 0) {
            kava.Kava.getStdout().write(System.in.read());         
        }
    }
}
