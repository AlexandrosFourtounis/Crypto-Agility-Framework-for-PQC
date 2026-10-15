// Java - Deprecated MD5 Hashing
/* Save this file as "VulnerableHash.java" */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VulnerableHash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String password = "super_secret_password";

        // Use of insecure hashing algorithm MD5
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());

        // Print the hash
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        System.out.println("MD5 Hash: " + hexString.toString());
    }
}