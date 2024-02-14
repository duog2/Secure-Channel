import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

public class EchoServer2 {
    private static PublicKey ServerPublicKeyEncrypt;
    private static PrivateKey ServerPrivateKeyEncrypt;
    private static PublicKey ServerPublicKeySign;
    private static PrivateKey ServerPrivateKeySign;
    private static PublicKey ClientPublicKeyEncrypt;
    private static PrivateKey ClientPrivateKeyEncrypt;
    private static PublicKey ClientPublicKeySign;
    private static PrivateKey ClientPrivateKeySign;

    private static SecretKey masterKey;
    private SecretKey clientServerKey;
    private SecretKey serverClientKey;

    private static SecretKey deriveKey(String purpose, SecretKey sharedSecret)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(purpose.toCharArray(), sharedSecret.getEncoded(), 65536, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derivedKey = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(derivedKey, "AES");
    }

    private static SecretKey receiveMasterKey(byte[] secretkey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, ServerPrivateKeyEncrypt);
        byte[] decryptedBytes = cipher.doFinal(secretkey);
        masterKey = new SecretKeySpec(decryptedBytes, "AES");
        return masterKey;
    }

    private static void sendSecretKeyToClient(SecretKey masterKey, DataOutputStream out)
            throws IOException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ClientPublicKeyEncrypt);
        byte[] encryptedMasterKey = cipher.doFinal(masterKey.getEncoded());
        out.write(encryptedMasterKey);
    }

    public void loadServerKeysFromKeystore(String password) throws Exception {
        try (FileInputStream fis = new FileInputStream("cybr372.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fis, password.toCharArray());

            KeyPair clientEncryptKeyPair = getKeyPairFromKeyStore(keyStore, password, "server_encrypt_key");
            ServerPublicKeyEncrypt = clientEncryptKeyPair.getPublic();
            ServerPrivateKeyEncrypt = clientEncryptKeyPair.getPrivate();

            KeyPair clientSignKeyPair = getKeyPairFromKeyStore(keyStore, password, "server_sign_key");
            ServerPublicKeySign = clientSignKeyPair.getPublic();
            ServerPrivateKeySign = clientSignKeyPair.getPrivate();
        }
    }

    public void loadClientKeysFromKeystore(String password) throws Exception {
        try (FileInputStream fis = new FileInputStream("cybr372.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(fis, password.toCharArray());

            KeyPair clientEncryptKeyPair = getKeyPairFromKeyStore(keyStore, password, "client_encrypt_key");
            ClientPublicKeyEncrypt = clientEncryptKeyPair.getPublic();
            ClientPrivateKeyEncrypt = clientEncryptKeyPair.getPrivate();

            KeyPair clientSignKeyPair = getKeyPairFromKeyStore(keyStore, password, "client_sign_key");
            ClientPublicKeySign = clientSignKeyPair.getPublic();
            ClientPrivateKeySign = clientSignKeyPair.getPrivate();
        }
    }
    private static Set<ByteBuffer> seenNonces = new HashSet<>();

    private KeyPair getKeyPairFromKeyStore(KeyStore keyStore, String password, String alias) throws Exception {
        Key key = keyStore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        throw new Exception("Invalid key pair in keystore");
    }

    public void start(int port) throws Exception {
        try(ServerSocket serverSocket = new ServerSocket(port);
            Socket clientSocket = serverSocket.accept();
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream in = new DataInputStream(clientSocket.getInputStream())) {
            int numBytes;
            byte[] keys = new byte[256];
            while ((numBytes = in.read(keys)) != -1) {
                SecretKey secretKey = receiveMasterKey(keys);
                sendSecretKeyToClient(secretKey, out);
                clientServerKey = deriveKey("client-server", secretKey);
                serverClientKey = deriveKey("server-client", secretKey);
                byte[] encryptedMessage = new byte[44];
                while ((numBytes = in.read(encryptedMessage)) != -1) {
                    System.out.println("Server from port " + port + " received your message! Please be patient with the decryption process...\n");
                    String decrypted = decrypt(encryptedMessage, clientServerKey);
                    System.out.println("Server receive message:" + decrypted + "\n");
                    byte[] encrypted = encrypt(decrypted, serverClientKey);
                    out.write(encrypted);
                }
            }
        }catch (IOException | InvalidKeySpecException e) {
            System.out.println("Error when initializing connection: " + e.getMessage() + "\n");
        }


    }
    private static ByteBuffer generateNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[8];
        secureRandom.nextBytes(nonce);
        return ByteBuffer.wrap(nonce);
    }
    private static byte[] encrypt(String plaintext, SecretKey secretKey) throws Exception {
        ByteBuffer nonce = generateNonce();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = generateRandomIV();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        ByteBuffer buffer = ByteBuffer.allocate(8 + iv.length + encryptedBytes.length );
        buffer.put(nonce);
        buffer.put(iv);
        buffer.put(encryptedBytes);
        return buffer.array();
    }

    private static boolean isNonceUnique(ByteBuffer nonce) {
        if(seenNonces.contains(nonce)){
            return false;
        }
        return true;
    }
    private static String decrypt(byte[] ciphertextWithIV, SecretKey secretKey) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(ciphertextWithIV);

        byte[] nonceBytes = new byte[8];
        buffer.get(nonceBytes);
        ByteBuffer nonce = ByteBuffer.wrap(nonceBytes);

        if (!isNonceUnique(nonce)) {
            throw new RuntimeException("Nonce has been used before \n");
        }
        else{
            System.out.println("Nonce is valid, process to decryption...\n");
            seenNonces.add(nonce);
        }
        byte[] iv = new byte[12];
        buffer.get(iv);
        byte[] encryptedBytes = new byte[buffer.remaining()];
        buffer.get(encryptedBytes);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] generateRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }



    public static void main(String[] args) throws Exception {
        EchoServer2 server = new EchoServer2();
        server.loadClientKeysFromKeystore("badpassword");
        server.loadServerKeysFromKeystore("badpassword");
        server.start(4444);
        server.start(4444);
        server.start(4444);
        server.start(4444);
    }
}