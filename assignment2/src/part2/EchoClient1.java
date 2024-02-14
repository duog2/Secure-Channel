import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;


public class EchoClient1 {
    enum Order {
        SIGN_AND_ENCRYPT,
        ENCRYPT_THEN_SIGN
    }

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static PublicKey ServerPublicKeyEncrypt;
    private static PrivateKey ServerPrivateKeyEncrypt;
    private static PublicKey ServerPublicKeySign;
    private static PrivateKey ServerPrivateKeySign;
    private static PublicKey ClientPublicKeyEncrypt;
    private static PrivateKey ClientPrivateKeyEncrypt;
    private static PublicKey ClientPublicKeySign;
    private static PrivateKey ClientPrivateKeySign;

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
    public byte[] SignAndEncrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ClientPublicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ClientPrivateKeySign);
        signature.update(originalBytes);
        byte[] digitalSignature = signature.sign();

        int totalLength = cipherTextBytes.length + digitalSignature.length;
        byte[] concatenatedArray = new byte[totalLength];

        System.arraycopy(digitalSignature, 0, concatenatedArray, 0, digitalSignature.length);
        System.arraycopy(cipherTextBytes, 0, concatenatedArray, digitalSignature.length, cipherTextBytes.length);

        return concatenatedArray;
    }
    public byte[] EncryptThenSign(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ClientPublicKeyEncrypt);
        byte[] originalBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ClientPrivateKeySign);
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
        cipher.init(Cipher.DECRYPT_MODE, ServerPrivateKeyEncrypt);

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(ServerPublicKeySign);
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
        sig.initVerify(ServerPublicKeySign);
        sig.update(encryptedMessage);
        boolean signatureValid = sig.verify(signature);
        if(signatureValid){
            System.out.println("Signature checks out; written by key owner.");
        }else{
            throw new IllegalArgumentException("Signature does not match");
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, ServerPrivateKeyEncrypt);

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);


        return decryptedMessage;
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
                System.out.println("Client's received the message with order " + order + " please be patient with the decryption process...");
                System.out.println("Server sending back cleartext:" + reply);
                return reply;
            } else if (order.equals(Order.ENCRYPT_THEN_SIGN)) {
                byte[] EncryptThenSign = EncryptThenSign(msg);
                out.write(EncryptThenSign);
                out.flush();
                byte [] data = new byte[512];
                in.read(data);
                String reply = DecryptEncryptThenSign(data);
                System.out.println("Client's received the message with order " + order + " please be patient with the decryption process...");
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
                if(newKeystorePassword.equals(keystorePassword)){
                    System.out.println("Password change failed. Please choose a different password.");
                    return;
                }
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    System.out.println("Password has been changed!");
                    EchoClient1 client = new EchoClient1();
                    client.startConnection("127.0.0.1", 4444);
                    client.loadClientKeysFromKeystore(newKeystorePassword);
                    client.loadServerKeysFromKeystore(newKeystorePassword);
                    Scanner scanner3 = new Scanner(System.in);
                    System.out.println("Enter your order:");
                    String orderInput = scanner3.nextLine();
                    Order order = Order.valueOf(orderInput.toUpperCase());
                    client.sendMessage("12345678", order);
                    client.sendMessage("ABCDEFGH", order);
                    client.sendMessage("87654321", order);
                    client.sendMessage("HGFEDCBA", order);
                    client.stopConnection();
                }else {
                    System.out.println("Password change failed. Please check your old password.");
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }
        else{
            EchoClient1 client = new EchoClient1();
            client.startConnection("127.0.0.1", 4444);
            client.loadClientKeysFromKeystore(args[0]);
            client.loadServerKeysFromKeystore(args[0]);
            client.sendMessage("12345678", Order.valueOf(args[1]));
            client.sendMessage("ABCDEFGH", Order.valueOf(args[1]));
            client.sendMessage("87654321", Order.valueOf(args[1]));
            client.sendMessage("HGFEDCBA", Order.valueOf(args[1]));
            client.stopConnection();
        }
    }
}
