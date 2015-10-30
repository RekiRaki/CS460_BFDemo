import uk.ac.ic.doc.jpair.api.Pairing;
import uk.ac.ic.doc.jpair.ibe.BFCipher;
import uk.ac.ic.doc.jpair.ibe.BFCtext;
import uk.ac.ic.doc.jpair.ibe.key.BFUserPrivateKey;
import uk.ac.ic.doc.jpair.ibe.key.BFUserPublicKey;
import uk.ac.ic.doc.jpair.pairing.PairingFactory;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Original created by Jacob on 10/21/2015.
 * Modified by David
 */
public class BFDemo {
    public static void main(String[] args) {
        //Setup the encryption scheme - this part goes on the server
    	System.out.println("Initializing PKG ... ");
        SecureRandom random = new SecureRandom();
        Pairing pair = PairingFactory.ssTate(128, 512, random);
        BFCipher cipher = new BFCipher();
        KeyPair masterPair = cipher.setup(pair, random);

        //Grab a private/public key from the scheme with a given ID - query the server for these (see below)
        System.out.println("Please enter the recipient's ID: ");
        Scanner kb = new Scanner(System.in);
        String receiptID = kb.nextLine();
        KeyPair userPair = cipher.extract(masterPair, receiptID, random);
        BFUserPublicKey publicKey = (BFUserPublicKey) userPair.getPublic();
        BFUserPrivateKey privateKey = (BFUserPrivateKey) userPair.getPrivate();
        System.out.println("Received " + receiptID + "'s public key.");
        kb.nextLine();

        //Grab some test input to encrypt with a person's public key
        System.out.print("Enter a string to encrypt: ");
        String testLine = kb.nextLine();

        //Encrypt and print - query the server for the public key
        System.out.println("Encrypting message ... ");
        BFCtext cipherText = cipher.encrypt(publicKey, testLine.getBytes(), random);
        System.out.println("Ciphertext: ");
        System.out.println("U: " + cipherText.getU()
                + "\nV: " + new String(cipherText.getV())
                + "\nW: " + new String(cipherText.getW()));
        kb.nextLine();
        kb.close();

        //Decrypt and print - query the server for the private key AND DISALLOW FUTURE REQUESTS
        System.out.println("\nDecrypting message ... ");
        byte[] plainText = cipher.decrypt(cipherText, privateKey);
        System.out.println("Decrypted plaintext: ");
        System.out.println(new String(plainText));
    }
}
