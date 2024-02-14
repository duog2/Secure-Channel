import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private PublicKey publicKeyEncrypt;
    private PrivateKey privateKeyEncrypt;
    private PublicKey publicKeySign;
    private PrivateKey privateKeySign;
    private DataOutputStream out;
    private DataInputStream in;

    enum Order {
        SIGN_AND_ENCRYPT,
        ENCRYPT_THEN_SIGN
    }
    public void generateRSAKeyEncrypt(int Keylength) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(Keylength);
        KeyPair server = keyPairGenerator.generateKeyPair();
        publicKeyEncrypt = server.getPublic();
        privateKeyEncrypt = server.getPrivate();
        byte[] publicKeyBytes = publicKeyEncrypt.getEncoded();
        byte[] privateKeyBytes = privateKeyEncrypt.getEncoded();
        FileOutputStream fos1 = new FileOutputStream("Server_Encrypt_Public.key");
        FileOutputStream fos2 = new FileOutputStream("Server_Encrypt_Private.key");
        System.out.println("Public Key (Base64):");
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyEncrypt.getEncoded());
        System.out.println(publicKeyBase64);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKeyEncrypt;
        System.out.println("Modulus: " + rsaPublicKey.getModulus());
        System.out.println("Exponent: " + rsaPublicKey.getPublicExponent());
        fos1.write(publicKeyBytes);
        fos2.write(privateKeyBytes);
        fos1.close();
        fos2.close();
    }
    public void generateRSAKeySign(int Keylength) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(Keylength);
        KeyPair server = keyPairGenerator.generateKeyPair();
        publicKeySign = server.getPublic();
        privateKeySign = server.getPrivate();
        byte[] publicKeyBytes = publicKeySign.getEncoded();
        byte[] privateKeyBytes = privateKeySign.getEncoded();
        FileOutputStream fos1 = new FileOutputStream("Server_Sign_Public.key");
        FileOutputStream fos2 = new FileOutputStream("Server_Sign_Private.key");
        System.out.println("Public Key (Base64):");
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeySign.getEncoded());
        System.out.println(publicKeyBase64);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKeySign;
        System.out.println("Modulus: " + rsaPublicKey.getModulus());
        System.out.println("Exponent: " + rsaPublicKey.getPublicExponent());
        fos1.write(publicKeyBytes);
        fos2.write(privateKeyBytes);
        fos1.close();
        fos2.close();
    }
    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port, Order order) {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[512];
            int numBytes;
            while ((numBytes = in.read(data)) != -1) {
                if(order.equals(Order.SIGN_AND_ENCRYPT)) {
                    String msg = DecryptSignAndEncrypt(data);
                    System.out.println("Server received cleartext:" + msg);
                    out.write(SignAndEncrypt(msg));
                }else if(order.equals(Order.ENCRYPT_THEN_SIGN)){
                    String msg = DecryptEncryptThenSign(data);
                    System.out.println("Server received cleartext:" + msg);
                    out.write(EncryptThenSign(msg));
                }
            }
            out.flush();
            stop();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public byte[] SignAndEncrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeySign);
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
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKeySign);
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
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey("Client_Encrypt_Private.key"));

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(getPublicKey("Client_Sign_Public.key"));
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
        sig.initVerify(getPublicKey("Client_Sign_Public.key"));
        sig.update(encryptedMessage);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out, process to decryption....");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey("Client_Encrypt_Private.key"));

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);


        return decryptedMessage;
    }
    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

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


    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        EchoServer server = new EchoServer();
        int length = Integer.parseInt(args[0]);
        Order order= Order.valueOf(args[1]);
        server.generateRSAKeyEncrypt(length);
        server.generateRSAKeySign(length);
        server.start(4444,order);
    }

}



