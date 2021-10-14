package com.clevergo.cypherlib;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.*;

public class Cypher {

    private static final List<String> upperAlphabets = Arrays.asList(
            "A", "B", "C", "D", "E", "F", "G",
            "H", "I", "J", "K", "L", "M", "N",
            "O", "P", "Q", "R", "S", "T", "U",
            "V", "W", "X", "Y", "Z");

    private static final List<String> upperAlphabetsRev = Arrays.asList(
            "Z", "Y", "X", "W", "V", "U", "T",
            "S", "R", "Q", "P", "O", "N", "M",
            "L", "K", "J", "I", "H", "G", "F",
            "E", "D", "C", "B", "A");

    private static List<String> lowerAlphabets = new ArrayList<>();
    private static List<String> lowerAlphabetsRev = new ArrayList<>();

    private static void init() {
        for (String c : upperAlphabets) {
            lowerAlphabets.add(c.toLowerCase());
        }

        for (String c : upperAlphabetsRev) {
            lowerAlphabetsRev.add(c.toLowerCase());
        }
    }

    public static String encryptROT(String value, int n) {
        if (lowerAlphabets == null || lowerAlphabets.isEmpty()) init();

        char[] encryptedWord = new char[value.length()];

        int pos, newPos, position = -1;
        boolean upper;
        for (char c : value.toCharArray()) {
            position++;

            pos = upperAlphabets.indexOf(String.valueOf(c));
            if (pos == -1) {
                pos = lowerAlphabets.indexOf(String.valueOf(c));
                upper = false;
            } else {
                upper = true;
            }

            newPos = (pos + n) > 25 ? (pos + n) % 26 : (pos + n);

            encryptedWord[position] = upper ? upperAlphabets.get(newPos).charAt(0) : lowerAlphabets.get(newPos).charAt(0);
        }
        return String.valueOf(encryptedWord);
    }

    public static String decryptROT(String encryptedWord, int n) {
        if (lowerAlphabetsRev == null || lowerAlphabetsRev.isEmpty()) init();

        char[] decryptedWord = new char[encryptedWord.length()];

        int pos = 0, originalPos = 0, position = -1;
        boolean upper;
        for (char c : encryptedWord.toCharArray()) {
            position++;

            pos = upperAlphabetsRev.indexOf(String.valueOf(c));
            if (pos == -1) {
                upper = false;
                pos = lowerAlphabetsRev.indexOf(String.valueOf(c));
            } else {
                upper = true;
            }

            originalPos = (pos + n) > 25 ? (pos + n) % 26 : (pos + n);

            decryptedWord[position] = upper ? upperAlphabetsRev.get(originalPos).charAt(0) : lowerAlphabetsRev.get(originalPos).charAt(0);
        }
        return String.valueOf(decryptedWord);
    }

    public static String encryptVigenere(String toEncrypt, String key) {
        if (toEncrypt.length() == key.length()) {
            toEncrypt = toEncrypt.toUpperCase();
            key = key.toUpperCase();

            StringBuilder encryptedWord = new StringBuilder();

            for (int i = 0; i < toEncrypt.length(); i++) {
                int a = (toEncrypt.charAt(i) + key.charAt(i)) % 26;
                a += 'A';
                encryptedWord.append((char) a);
            }

            return encryptedWord.toString();
        } else {
            return "Length doesn't match";
        }
    }

    public static String decryptVigenere(String encryptedWord, String key) {
        encryptedWord = encryptedWord.toUpperCase();
        key = key.toUpperCase();

        StringBuilder originalStr = new StringBuilder();

        for (int i = 0; i < encryptedWord.length(); i++) {
            int a = (encryptedWord.charAt(i) - key.charAt(i) + 26) % 26;
            a += 'A';
            originalStr.append((char) a);
        }

        return originalStr.toString();
    }

    public static String stringToBinary(String toEncrypt, boolean prettyFormat) {
        StringBuilder stringBuilder = new StringBuilder();
        if (prettyFormat) {
            for (char c : toEncrypt.toCharArray()) {
                stringBuilder.append(String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0"));
            }

            String[] prettyFormatted = stringBuilder.toString().split("(?<=\\G.{" + 8 + "})");
            stringBuilder = null;
            stringBuilder = new StringBuilder();
            for (String str : prettyFormatted) {
                stringBuilder.append(str).append(" ");
            }
        } else {
            for (char c : toEncrypt.toCharArray()) {
                stringBuilder.append(String.format("%8s", Integer.toBinaryString(c)).replaceAll(" ", "0"));
            }
        }
        return stringBuilder.toString();
    }

    public static String binaryToString(String toDecrypt) {
        StringBuilder stringBuilder = new StringBuilder();
        String[] defaultBinaryFormat = toDecrypt.replaceAll(" ", "").split("(?<=\\G.{" + 8 + "})");

        for (String str : defaultBinaryFormat) {
            stringBuilder.append((char) Integer.parseInt(str, 2));
        }

        return stringBuilder.toString();
    }

    public static String stringToAscii(String toEncrypt, boolean prettyFormat) {
        StringBuilder sb = new StringBuilder();
        String asciiVal;
        for (char c : toEncrypt.toCharArray()) {
            asciiVal = String.valueOf((int) c);
            if (asciiVal.length() == 2) {
                asciiVal = String.format("%03d", (int) c);
            }

            sb.append(prettyFormat ? asciiVal + " " : asciiVal);
        }

        return sb.toString();
    }

    public static String asciiToString(String toDecrypt) {
        StringBuilder sb = new StringBuilder();
        String[] asciiSplited = toDecrypt.replaceAll(" ", "").split("(?<=\\G.{" + 3 + "})");

        for (String s : asciiSplited) {
            char c = (char) Integer.parseInt(s);
            sb.append(c);
        }
        return sb.toString();
    }

    public static String stringToHex(String toEncrypt) {
        StringBuilder sb = new StringBuilder();
        for (char c : toEncrypt.toCharArray()) {
            sb.append(Integer.toHexString(c));
        }

        return sb.toString();
    }

    public static String hexToString(String hexCode) {
        StringBuilder sb = new StringBuilder();
        String[] hexSplited = hexCode.split("(?<=\\G.{" + 2 + "})");

        for (String str : hexSplited) {
            sb.append(((char) Integer.parseUnsignedInt(str, 16)));
        }

        return sb.toString();
    }

    public static String normalToReverse(String normalString) {
        StringBuilder sb = new StringBuilder(normalString);
        return sb.reverse().toString();
    }

    public static String reverseToNormal(String reversedString) {
        StringBuilder sb = new StringBuilder(reversedString);
        return sb.reverse().toString();
    }

    public static String normalToMirrorString(String toMirror) {
        if (lowerAlphabets.isEmpty()) init();
        StringBuilder sb = new StringBuilder();

        boolean upper;
        int pos, newPos;
        for (char c : toMirror.toCharArray()) {
            pos = upperAlphabets.indexOf(String.valueOf(c));
            if (pos == -1) {
                upper = false;
                pos = lowerAlphabets.indexOf(String.valueOf(c));
            } else {
                upper = true;
            }
            newPos = 25 - pos;
            sb.append(upper ? upperAlphabets.get(newPos).charAt(0) : lowerAlphabets.get(newPos).charAt(0));
        }

        return sb.toString();
    }

    public static String mirrorToNormal(String mirroredText) {
        if (lowerAlphabetsRev.isEmpty()) init();
        StringBuilder sb = new StringBuilder();

        boolean upper;
        int pos, newPos;
        for (char c : mirroredText.toCharArray()) {
            pos = upperAlphabetsRev.indexOf(String.valueOf(c));
            if (pos == -1) {
                upper = false;
                pos = lowerAlphabetsRev.indexOf(String.valueOf(c));
            } else {
                upper = true;
            }

            newPos = 25 - pos;
            sb.append(upper ? upperAlphabetsRev.get(newPos).charAt(0) : lowerAlphabetsRev.get(newPos).charAt(0));
        }

        return sb.toString();
    }

    public static String hashString(String toHash, HashAlgorithms algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm.toString());
        byte[] bytes = md.digest(toHash.getBytes(StandardCharsets.UTF_8));

        BigInteger bi = new BigInteger(1, bytes);
        StringBuilder sb = new StringBuilder(bi.toString(16));

        while (sb.length() < 32) sb.insert(0, "0");
        return sb.toString();
    }

    public static String encryptCaesar(String toEncrypt, int shiftTo) throws IllegalArgumentException {

        if (shiftTo >= 26 || shiftTo < 0) {
            throw new IllegalArgumentException("shiftTo should be lesser than 26 and greater than 0");
        }

        char[] encryptedString = new char[toEncrypt.length()];
        int position = -1, pos, newPos;
        boolean upper;
        for (char c : toEncrypt.toCharArray()) {
            position++;
            pos = upperAlphabets.indexOf(String.valueOf(c));
            if (pos == -1) {
                upper = false;
                pos = lowerAlphabets.indexOf(String.valueOf(c));
            } else {
                upper = true;
            }

            newPos = (pos + shiftTo) % 26;

            encryptedString[position] = upper ? upperAlphabets.get(newPos).charAt(0) : lowerAlphabets.get(newPos).charAt(0);
        }

        return String.valueOf(encryptedString);
    }

    public static String decryptCaesar(String toDecrypt, int shiftTo) {
        if (shiftTo >= 26 || shiftTo < 0) {
            throw new IllegalArgumentException("shiftTo should be lesser than 26 and greater than 0");
        }

        char[] decryptedString = new char[toDecrypt.length()];
        int position = -1, pos, newPos;
        boolean upper;
        for (char c : toDecrypt.toCharArray()) {
            position++;
            pos = upperAlphabetsRev.indexOf(String.valueOf(c));
            if (pos == -1) {
                upper = false;
                pos = lowerAlphabetsRev.indexOf(String.valueOf(c));
            } else {
                upper = true;
            }

            newPos = (pos + shiftTo) % 26;

            decryptedString[position] = upper ? upperAlphabetsRev.get(newPos).charAt(0) : lowerAlphabetsRev.get(newPos).charAt(0);
        }

        return String.valueOf(decryptedString);
    }

    public static String generatePassword(int n) {
        final String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+}{";
        char[] password = new char[n];
        Random random = new Random();

        for (int i = 0; i < n; i++) {
            password[i] = passwordChars.charAt(random.nextInt(passwordChars.length() - 1));
        }

        return String.valueOf(password);
    }

    public static class AdvancedCypher {
        public static String encryptAES(String toEncrypt, final String key1, final String key2) throws Exception {
            try {
                byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(key1.toCharArray(), key2.getBytes(), 65536, 256);
                SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                return Base64.getEncoder().encodeToString(cipher.doFinal(toEncrypt.getBytes(StandardCharsets.UTF_8)));
            } catch (Exception ex) {
                throw new Exception(ex);
            }
        }

        public static String decryptAES(String toDecrypt, final String key1, final String key2) throws Exception {
            try {
                byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(key1.toCharArray(), key2.getBytes(), 65536, 256);
                SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

                return new String(cipher.doFinal(Base64.getDecoder().decode(toDecrypt)));
            } catch (Exception ex) {
                throw new Exception(ex);
            }
        }

        public static String encrypt3DES(String toEncrypt, final String key1, final String key2) throws Exception {
            byte[] secretKey = key1.getBytes();
            byte[] ivArray = key2.getBytes();

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "TripleDES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivArray);

            Cipher cipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encryptedMessage = cipher.doFinal(toEncrypt.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedMessage);
        }

        public static String decrypt3DES(String toDecrypt, final String key1, final String key2) throws Exception {
            byte[] secretKey = key1.getBytes();
            byte[] ivArray = key2.getBytes();

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "TripleDES");
            IvParameterSpec ivSpec = new IvParameterSpec(ivArray);

            Cipher cipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

            byte[] toDecode = Base64.getDecoder().decode(toDecrypt);

            return new String(cipher.doFinal(toDecode));
        }
    }
}
