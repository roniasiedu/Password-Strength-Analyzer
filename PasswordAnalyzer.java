// Smart Password Strength Analyzer
// Evaluates password strength using entropy, dictionary checks, and pattern detection

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class PasswordAnalyzer {
    private static final String COMMON_PASSWORDS_FILE = "common_passwords.txt"; // List of weak passwords
    private static final int STRONG_PASSWORD_ENTROPY = 50;

    // Method to calculate Shannon entropy
    public double calculateEntropy(String password) {
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : password.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (int count : freqMap.values()) {
            double p = (double) count / password.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy * password.length();
    }

    // Check if password exists in common password dictionary
    public boolean isCommonPassword(String password) {
        try {
            List<String> commonPasswords = Files.readAllLines(Paths.get(COMMON_PASSWORDS_FILE));
            return commonPasswords.contains(password);
        } catch (IOException e) {
            System.out.println("Error reading common password file.");
            return false;
        }
    }

    // Detects simple patterns: sequential numbers, repeated characters, keyboard sequences
    public boolean hasWeakPattern(String password) {
        return Pattern.matches(".*(1234|abcd|qwerty|password|1111).*", password.toLowerCase()) ||
               Pattern.matches(".*(.)\\1{3,}.*", password); // Repeated characters (e.g., "aaaa", "bbbb")
    }

    // Analyzes password and returns a strength score
    public String analyzePassword(String password) {
        double entropy = calculateEntropy(password);
        boolean isWeak = isCommonPassword(password) || hasWeakPattern(password);

        System.out.println("Password Entropy: " + entropy);

        if (isWeak) return "❌ Weak Password (Common or Pattern-Based)";
        if (entropy < STRONG_PASSWORD_ENTROPY) return "⚠️ Medium Password (Low Entropy)";
        return "✅ Strong Password";
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        PasswordAnalyzer analyzer = new PasswordAnalyzer();

        System.out.print("Enter a password to analyze: ");
        String password = scanner.nextLine();

        System.out.println("Strength: " + analyzer.analyzePassword(password));
    }
}
