package com.jtk.crypto;

import com.jtk.crypto.symmetric.JTKSymEncryption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);
    public static final Scanner scanner = new Scanner(new InputStreamReader(System.in));

    public static void main(String[] args) throws IOException {
        Properties properties = new Properties();
        properties.load(new FileReader(args[0]));
        log.info("Please enter passphrase:");
        char[] passphrase = scanner.nextLine().toCharArray();
        log.info("Are you encrypting (Y/N):");
        String encrypting = scanner.nextLine();
        Boolean isEnc = encrypting.equalsIgnoreCase("Y")? true : false;
        JTKSymEncryption crypto = new JTKSymEncryption(passphrase, properties);
        if(isEnc){
            encrypt(passphrase,crypto);
        }else {
            decrypt(passphrase,crypto);
        }

    }

    private static void decrypt(char[] passphrase, JTKSymEncryption crypto) {
        log.info("please enter file to decrypt:");
        String file = scanner.nextLine();
        //String fileDecrpt = file+"-decrypt";
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                String decryptedText = crypto.decryptMessage(Base64.getDecoder().decode(line));
                //bufferedWriter.write(decryptedText + "\n");
                log.info("decrypted line :{}",decryptedText);
            }
        } catch (Exception e) {
            log.error("Unexpected Exception", e);
        }

    }

    private static void encrypt(char[] passphrase, JTKSymEncryption crypto) {
        log.info("please enter file to encrypt:");
        String file = scanner.nextLine();
        String fileEncrpt = file+"-encrypt";

        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
             BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(fileEncrpt))) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                byte[] encryptedText = crypto.encryptMessage(line);
                bufferedWriter.write(Base64.getEncoder().encodeToString(encryptedText) + "\n");
            }
        } catch (Exception e) {
            log.error("Unexpected Exception", e);
        }

    }
}
