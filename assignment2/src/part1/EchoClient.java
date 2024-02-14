import javax.crypto.Cipher;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoClient {
    enum Order {
        SIGN_AND_ENCRYPT,
        ENCRYPT_THEN_SIGN
    }

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private PublicKey publicKey_Encrypt;
    private static PrivateKey privateKey_Encrypt;

    private PublicKey publicKey_Sign;
    private PrivateKey privateKey_Sign;

    public void generateRSAKey_Encrypt(int Keylength) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(Keylength);
        KeyPair client = keyPairGenerator.generateKeyPair();
        publicKey_Encrypt = client.getPublic();
        privateKey_Encrypt = client.getPrivate();
        byte[] publicKeyBytes = publicKey_Encrypt.getEncoded();
        byte[] privateKeyBytes = privateKey_Encrypt.getEncoded();
        FileOutputStream fos1 = new FileOutputStream("Client_Encrypt_Public.key");
        FileOutputStream fos2 = new FileOutputStream("Client_Encrypt_Private.key");
        System.out.println("Public Key (Base64):");
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey_Encrypt.getEncoded());
        System.out.println(publicKeyBase64);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey_Encrypt;
        System.out.println("Modulus: " + rsaPublicKey.getModulus());
        System.out.println("Exponent: " + rsaPublicKey.getPublicExponent());

        fos1.write(publicKeyBytes);
        fos2.write(privateKeyBytes);
        fos1.close();
        fos2.close();

    }

    public void generateRSAKey_Sign(int Keylength) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(Keylength);
        KeyPair client = keyPairGenerator.generateKeyPair();
        publicKey_Sign = client.getPublic();
        privateKey_Sign = client.getPrivate();
        byte[] publicKeyBytes = publicKey_Sign.getEncoded();
        byte[] privateKeyBytes = privateKey_Sign.getEncoded();
        FileOutputStream fos1 = new FileOutputStream("Client_Sign_Public.key");
        FileOutputStream fos2 = new FileOutputStream("Client_Sign_Private.key");
        System.out.println("Public Key (Base64):");
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey_Sign.getEncoded());
        System.out.println(publicKeyBase64);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey_Sign;
        System.out.println("Modulus: " + rsaPublicKey.getModulus());
        System.out.println("Exponent: " + rsaPublicKey.getPublicExponent());

        fos1.write(publicKeyBytes);
        fos2.write(privateKeyBytes);
        fos1.close();
        fos2.close();

    }

    public byte[] SignAndEncrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey_Encrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey_Sign);
        signature.update(originalBytes);

        byte[] digitalSignature = signature.sign();

        int totalLength = cipherTextBytes.length + digitalSignature.length;

        byte[] concatenatedArray = new byte[totalLength];

        System.arraycopy(digitalSignature, 0, concatenatedArray, 0, digitalSignature.length);

        System.arraycopy(cipherTextBytes, 0, concatenatedArray, cipherTextBytes.length, digitalSignature.length);

        return concatenatedArray;
    }
    public byte[] EncryptThenSign(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey_Encrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey_Sign);
        signature.update(cipherTextBytes);

        byte[] digitalSignature = signature.sign();

        int totalLength = cipherTextBytes.length + digitalSignature.length;

        byte[] concatenatedArray = new byte[totalLength];

        System.arraycopy(digitalSignature, 0, concatenatedArray, 0, digitalSignature.length);

        System.arraycopy(cipherTextBytes, 0, concatenatedArray, cipherTextBytes.length, digitalSignature.length);

        return concatenatedArray;
    }

    public static String DecryptSignAndEncrypt(byte[] signedAndEncryptedMessage) throws Exception {
        int signatureLength = 256;

        byte[] signature = new byte[signatureLength];
        byte[] encryptedMessage = new byte[signedAndEncryptedMessage.length - signatureLength];

        System.arraycopy(signedAndEncryptedMessage, 0, signature, 0, signatureLength);
        System.arraycopy(signedAndEncryptedMessage, signatureLength, encryptedMessage, 0, encryptedMessage.length);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey("Server_Encrypt_Private.key"));

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(getPublicKey("Server_Sign_Public.key"));
        sig.update(decryptedBytes);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out, process to decryption....");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }
        return decryptedMessage;
    }

    public static String DecryptEncryptThenSign(byte[] signedAndEncryptedMessage) throws Exception {
        int signatureLength = 256;

        byte[] signature = new byte[signatureLength];
        byte[] encryptedMessage = new byte[signedAndEncryptedMessage.length - signatureLength];

        System.arraycopy(signedAndEncryptedMessage, 0, signature, 0, signatureLength);
        System.arraycopy(signedAndEncryptedMessage, signatureLength, encryptedMessage, 0, encryptedMessage.length);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(getPublicKey("Server_Sign_Public.key"));
        sig.update(encryptedMessage);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out, process to decryption....");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey("Server_Encrypt_Private.key"));

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);


        return decryptedMessage;
    }
    public static PrivateKey getPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    public static PublicKey getPublicKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Setup the two way streams.
     *
     * @param ip   the address of the server
     * @param port port used by the server
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */

    public String sendMessage(String msg, Order order) {
        try {
            System.out.println("Client sending cleartext: " + msg);
            if (order.equals(Order.SIGN_AND_ENCRYPT)) {
                byte[] Sign_And_Encrypt = SignAndEncrypt(msg);
                out.write(Sign_And_Encrypt);
                out.flush();
                byte [] data = new byte[512];
                in.read(data);
                String reply = DecryptSignAndEncrypt(data);
                System.out.println("Server sending back cleartext:" + reply);
                return reply;
            } else if (order.equals(Order.ENCRYPT_THEN_SIGN)) {
                byte[] EncryptThenSign = EncryptThenSign(msg);
                out.write(EncryptThenSign);
                out.flush();
                byte [] data = new byte[512];
                in.read(data);
                String reply = DecryptEncryptThenSign(data);
                System.out.println("Server sending back cleartext:" + reply);
                return reply;
            }
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        return null;
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        EchoClient client = new EchoClient();
        client.startConnection("127.0.0.1", 4444);
        int length = Integer.parseInt(args[0]);
        Order order= Order.valueOf((args[1]));

        client.generateRSAKey_Encrypt(length);
        client.generateRSAKey_Sign(length);
        client.sendMessage("12345678",order);
        client.sendMessage("ABCDEFGH",order);
        client.sendMessage("87654321",order);
        client.sendMessage("HGFEDCBA",order);
        client.stopConnection();
    }
}
