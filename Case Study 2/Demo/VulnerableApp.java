import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Scanner;

public class VulnerableApp {
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);
    public static void main(String[] args) {
        System.out.println("=== Log4Shell Vulnerability Demo ===\n");
        System.out.println("This demo shows how Log4j automatically evaluates expressions in log messages.\n");
        Scanner scanner = new Scanner(System.in);
        try {
            while (true) {
                System.out.print("Enter username (or 'exit' to quit): ");
                String username = scanner.nextLine();
                
                if ("exit".equalsIgnoreCase(username)) {
                    System.out.println("Exiting demo...");
                    break;
                }
                if (username.isEmpty()) {
                    System.out.println("Username cannot be empty.\n");
                    continue;
                }
                logger.info("Login attempt for user: " + username);
                System.out.println("Input logged. Check the console output above.\n");
            }
        } finally {
            scanner.close();
        }
    }
}