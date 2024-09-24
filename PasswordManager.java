import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.PBEKeySpec;

import java.util.HashMap;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PasswordManager  {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException{
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter the passcode to access your passwords: ");
        String passcode = sc.nextLine();

        Path path = Paths.get("EncryptedPasswordFile.txt");
        HashMap<String, String> passwords;
        SecretKeySpec key;

        if (Files.exists(path)) {
            String[] pair = getSaltKeyPair().split(":");
            String saltString = pair[0];
            byte[] salt = Base64.getDecoder().decode(saltString);
            key = generateKey(salt, passcode);
            try{
                String decrypted = decryptPassword(pair[1], key);
                if (decrypted.equals(passcode)) {
                    System.out.println("Access granted.");
                } else {
                    System.out.println("Invalid passcode.");
                    System.exit(0);
                }
            }catch(Exception e){
                System.out.println("Invalid passcode.");
                System.exit(0);
            }
        }
        
        else {
            key = generatePasswordFile(passcode);
            File passwordFile = new File("EncryptedPasswordFile.txt");
            System.out.println("No password file found.\nGenerated password file: " + passwordFile.getAbsolutePath());
        }

        passwords = fileToHashMap(new File("EncryptedPasswordFile.txt")); 

        while (true) {
            System.out.println("\nChoose an option:");
            System.out.println("a: Add Password");
            System.out.println("r: Read Password");
            System.out.println("q: Quit");
            System.out.print("Option: ");
            String option = sc.nextLine();
            if (option.equalsIgnoreCase("a")) {
                System.out.print("Enter label: ");
                String label = sc.nextLine();
                System.out.print("Enter password: ");
                String password = sc.nextLine();
                addPassword(label, password, key, passwords);
            } else if (option.equalsIgnoreCase("r")) {
                System.out.print("Enter label: ");
                String label = sc.nextLine();
                getPassword(label, key, passwords);
            }
            else{
                System.out.println("Goodbye!");
                break;
            }
        }
        sc.close();
    }

    public static void addPassword(String label, String password, SecretKeySpec key, HashMap<String, String> passwords) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException  {
        String encryptedPassword = encryptPassword(password, key);
        if (passwords.containsKey(label)) {
            passwords.remove(label);
            passwords.put(label, encryptedPassword);
            hashMapToFile(passwords);
        }
        else{
            passwords.put(label, encryptedPassword);
            FileWriter writer = new FileWriter("EncryptedPasswordFile.txt", true);
            writer.append(label + ":" + encryptedPassword + "\n");
            writer.close();
        }
    }
    public static String encryptPassword(String password,SecretKeySpec key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException  {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte [] encryptedData = cipher.doFinal(password.getBytes());
        String messageString = new String(Base64.getEncoder().encode(encryptedData));
        return messageString;
    }
    
    public static void getPassword(String label, SecretKeySpec key, HashMap<String, String> passwords) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException  {
        try{
            String encryptedPassword = passwords.get(label);
            String message = decryptPassword(encryptedPassword, key);
            System.out.println("Found: " + message);
        } catch (Exception e)  {
            System.out.println("No password found for label: " + label);
        }
    }
    public static String decryptPassword(String encryptedPassword, SecretKeySpec key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException  {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte [] decodedData = Base64.getDecoder().decode(encryptedPassword);
        byte [] decryptedData = cipher.doFinal(decodedData);
        String message = new String(decryptedData);
        return message;
    }

    public static SecretKeySpec generatePasswordFile(String passcode) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = Base64.getEncoder().encodeToString(salt);
        salt = Base64.getDecoder().decode(saltString);

        SecretKeySpec key = generateKey(salt, passcode);

        String encryptedPasscode = encryptPassword(passcode, key);
        FileWriter writer = new FileWriter("EncryptedPasswordFile.txt", true);
        writer.write(saltString + ":" + encryptedPasscode + "\n");
        writer.close();

        return key;
    }

    public static SecretKeySpec generateKey(byte[] salt, String passcode) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, 600024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte[] encoded = sharedKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(encoded, "AES");
        return key;
    }
    
    public static HashMap<String, String> fileToHashMap(File passwordFile) throws FileNotFoundException {
        HashMap<String, String> passwordHashMap = new HashMap<String, String>();

        Scanner sc = new Scanner(passwordFile);
        sc.nextLine();
        while(sc.hasNextLine()) {
            String line = sc.nextLine();
            String[] tokens = line.split(":");
            passwordHashMap.put(tokens[0], tokens[1]);
        }
        sc.close();
        return passwordHashMap;
    }

    public static String getSaltKeyPair() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException {
        Scanner sc = new Scanner(new File("EncryptedPasswordFile.txt"));
        String s = sc.nextLine();
        sc.close();
        return s;
    }

    public static void hashMapToFile(HashMap<String, String> hashMap) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        String pair = getSaltKeyPair();
        FileWriter writer1 = new FileWriter("EncryptedPasswordFile.txt");
        writer1.write("");
        writer1.close();
        FileWriter writer = new FileWriter("EncryptedPasswordFile.txt", true);
        writer.write(pair + "\n");
        for (String key : hashMap.keySet()) {
            writer.write(key + ":" + hashMap.get(key) + "\n");
        }
        writer.close();   
    }
}