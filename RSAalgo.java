package Encryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSAalgo {

    public static void main(String[] args) {

        Scanner s = new Scanner(System.in);

        RSAalgo rsa = new RSAalgo (1024);

        System.out.println("Enter your message to encrypt");

        String message=s.next();

        String ciphertext = rsa.encrypt(message);

        System.out.println("Your encrypted Message" +"-->"+ ciphertext);

        System.out.println("Your decrypted Message"+"-->"+ rsa.decrypt(ciphertext));

    }

    private BigInteger modulus, privateKey, publicKey;

    public RSAalgo(int bits)
    {
        generateKeys(bits);
    }

    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(publicKey, modulus).toString();
    }

    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    public synchronized String decrypt(String encryptedMessage) {
        return new String((new BigInteger(encryptedMessage)).modPow(privateKey, modulus).toByteArray());
    }

    public synchronized BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(privateKey, modulus);
    }



    public synchronized void generateKeys(int bits) {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bits / 2, 100, r);
        BigInteger q = new BigInteger(bits / 2, 100, r);
        modulus = p.multiply(q);

        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        publicKey = new BigInteger("3");

        while (m.gcd(publicKey).intValue() > 1) {
            publicKey = publicKey.add(new BigInteger("2"));
        }

        privateKey = publicKey.modInverse(m);
    }
}

