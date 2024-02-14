import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;


public class EchoServer1 {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private static PublicKey ServerPublicKeyEncrypt;
    private static PrivateKey ServerPrivateKeyEncrypt;
    private static PublicKey ServerPublicKeySign;
    private static PrivateKey ServerPrivateKeySign;
    private static PublicKey ClientPublicKeyEncrypt;
    private static PrivateKey ClientPrivateKeyEncrypt;
    private static PublicKey ClientPublicKeySign;
    private static PrivateKey ClientPrivateKeySign;
    private DataOutputStream out;
    private DataInputStream in;

    enum Order {
        SIGN_AND_ENCRYPT,
        ENCRYPT_THEN_SIGN
    }
    public void loadServerKeysFromKeystore(String password) throws Exception {

        try (FileInputStream fis = new FileInputStream("cybr372.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fis, password.toCharArray());

            KeyPair clientEncryptKeyPair = getKeyPairFromKeyStore(keyStore, password,"server_encrypt_key");
            ServerPublicKeyEncrypt = clientEncryptKeyPair.getPublic();
            ServerPrivateKeyEncrypt = clientEncryptKeyPair.getPrivate();

            KeyPair clientSignKeyPair = getKeyPairFromKeyStore(keyStore, password,"server_sign_key");
            ServerPublicKeySign = clientSignKeyPair.getPublic();
            ServerPrivateKeySign = clientSignKeyPair.getPrivate();
        }
    }
    public void loadClientKeysFromKeystore(String password) throws Exception {

        try (FileInputStream fis = new FileInputStream("cybr372.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fis, password.toCharArray());

            KeyPair clientEncryptKeyPair = getKeyPairFromKeyStore(keyStore, password,"client_encrypt_key");
            ClientPublicKeyEncrypt = clientEncryptKeyPair.getPublic();
            ClientPrivateKeyEncrypt = clientEncryptKeyPair.getPrivate();

            KeyPair clientSignKeyPair = getKeyPairFromKeyStore(keyStore, password,"client_sign_key");
            ClientPublicKeySign = clientSignKeyPair.getPublic();
            ClientPrivateKeySign = clientSignKeyPair.getPrivate();
        }
    }

    private KeyPair getKeyPairFromKeyStore(KeyStore keyStore, String password, String alias) throws Exception {
        Key key = keyStore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        throw new Exception("Invalid key pair in keystore");
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
                    System.out.println("Serve's received message with order: " + order + " please be patient with the decryption process...");
                    String msg = DecryptSignAndEncrypt(data);
                    System.out.println("Server received cleartext:" + msg);
                    out.write(SignAndEncrypt(msg));
                }else if(order.equals(Order.ENCRYPT_THEN_SIGN)){
                    System.out.println("Serve's received message with order: " + order + " please be patient with the decryption process...");
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
        cipher.init(Cipher.ENCRYPT_MODE, ServerPublicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ServerPrivateKeySign);
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
        cipher.init(Cipher.ENCRYPT_MODE, ServerPublicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ServerPrivateKeySign);
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
        cipher.init(Cipher.DECRYPT_MODE,ClientPrivateKeyEncrypt);

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(ClientPublicKeySign);
        sig.update(decryptedBytes);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out; written by key owner.");
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
        sig.initVerify(ClientPublicKeySign);
        sig.update(encryptedMessage);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out; written by key owner.");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, ClientPrivateKeyEncrypt);

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
    public static void main(String[] args) throws Exception {
        String keystorePath = "cybr372.jks";
        if(args[0].equalsIgnoreCase("Change")) {
            System.out.println("User's required to change the password....");
            Scanner scanner1 = new Scanner(System.in);
            System.out.println("Enter your old password:");
            String keystorePassword = scanner1.nextLine();

            Scanner scanner2 = new Scanner(System.in);
            System.out.println("Enter your new password:");
            String newKeystorePassword = scanner2.nextLine();
            try {
                String command = String.format(
                        "keytool -storepasswd -keystore %s -storepass %s -new %s",
                        keystorePath, keystorePassword, newKeystorePassword
                );
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                if(newKeystorePassword.equals(keystorePassword)){
                    System.out.println("Password change failed. Please choose a different password.");
                    return;
                }
                if (exitCode == 0) {
                    System.out.println("Password has been changed!");
                    EchoServer1 server = new EchoServer1();
                    server.loadClientKeysFromKeystore(newKeystorePassword);
                    server.loadServerKeysFromKeystore(newKeystorePassword);
                    Scanner scanner3 = new Scanner(System.in);
                    System.out.println("Enter your order:");
                    String orderInput = scanner3.nextLine();
                    Order order = Order.valueOf(orderInput.toUpperCase());
                    System.out.println("Server's started, waiting for message....");
                    server.start(4444, order);
                } else {
                    System.out.println("Password change failed. Please check your old password.");
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }

        }
        else{
            EchoServer1 server = new EchoServer1();
            server.loadClientKeysFromKeystore(args[0]);
            server.loadServerKeysFromKeystore(args[0]);
            Order order = Order.valueOf(args[1]);
            System.out.println("Server's started, waiting for message....");
            server.start(4444, order);
        }
    }

}



