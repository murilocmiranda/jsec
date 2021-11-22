package io.sparkflows.aes;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.Console;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class JSec {
    private static final String ENC_DEC_PLAIN_TXT_PASS = "J!2n8uOu&%fwH5r#zm!Z";
    private static final String SALT = "1234567812345678";
    private static final String ALGO = "AES/CBC/PKCS5Padding";
    private final static String CMD_ENCRYPT = "encrypt";
    private final static String CMD_DECRYPT = "decrypt";

    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }
        SecretKey secretKey = AESUtil.getKeyFromPassword(ENC_DEC_PLAIN_TXT_PASS, SALT);
        if (args[0].equalsIgnoreCase(CMD_ENCRYPT)) {
            Console console = System.console();
            String plainText = new String(console.readPassword("Enter password: "));
            String encryptedPasswd = AESUtil.encrypt(ALGO, plainText, secretKey, AESUtil.generateIv(SALT));
            FileWriter fw = new FileWriter(args[1]);
            fw.write(encryptedPasswd);
            fw.close();
        } else if(args[0].equalsIgnoreCase(CMD_DECRYPT)){
            List<String> lines = Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8);
            lines.forEach(s -> {
                try {
                   String plainText = AESUtil.decrypt(ALGO, s, secretKey, AESUtil.generateIv(SALT));
                   System.out.println(plainText);
                } catch (NoSuchPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            });
        }

    }

    private static void printUsage() {
        System.err.println("USAGE");
        System.err.println("  $ jsec [command]");
        System.err.println("COMMANDS");
        System.err.println("  encrypt <file-path> encrypt the password and save it to a file");
        System.err.println("  decrypt <file-path> decrypt the file and display on console");

    }

}
