import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashSet;
import java.util.Set;

class EchoClient2 {

    private SecretKey clientServerKey;
    private SecretKey serverClientKey;
    private static PublicKey ServerPublicKeyEncrypt;
    private static PrivateKey ServerPrivateKeyEncrypt;
    private static PublicKey ServerPublicKeySign;
    private static PrivateKey ServerPrivateKeySign;
    private static PublicKey ClientPublicKeyEncrypt;
    private static PrivateKey ClientPrivateKeyEncrypt;
    private static PublicKey ClientPublicKeySign;
    private static PrivateKey ClientPrivateKeySign;

    private SecretKey generateRandomMasterKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static SecretKey receiveMasterKey(byte[] secretkey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, ClientPrivateKeyEncrypt);
        byte[] decryptedBytes = cipher.doFinal(secretkey);
        SecretKey masterKey = new SecretKeySpec(decryptedBytes, "AES");
        return masterKey;
    }

    private byte[] sendMasterKey(SecretKey masterKey)
            throws IOException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, ServerPublicKeyEncrypt);
        byte[] encrypted;
        encrypted = cipher.doFinal(masterKey.getEncoded());
        return encrypted;
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

    private KeyPair getKeyPairFromKeyStore(KeyStore keyStore, String password, String alias) throws Exception {
        Key key = keyStore.getKey(alias, password.toCharArray());
        if (key instanceof PrivateKey) {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        throw new Exception("Invalid key pair in keystore");
    }

    private static SecretKey deriveKey(String purpose, SecretKey sharedSecret)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(purpose.toCharArray(), sharedSecret.getEncoded(), 65536, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derivedKey = keyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(derivedKey, "AES");
    }
    private int count = 0;
    public void startConnection(String ip, int port, String msg, int countNum) {
        System.out.println("Client request a connection at port: " + port +"\n");
        try(Socket clientSocket = new Socket(ip, port);
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
            DataInputStream in = new DataInputStream(clientSocket.getInputStream())){
            SecretKey masterKey = generateRandomMasterKey();
            byte[] encryptedKey = sendMasterKey(masterKey);
            out.write(encryptedKey);
            byte[] data = new byte[256];
            in.read(data);
            SecretKey reply = receiveMasterKey(data);
            if (reply.equals(masterKey)) {
                clientServerKey = deriveKey("client-server", masterKey);
                serverClientKey = deriveKey("server-client", masterKey);
                System.out.println("Client sending cleartext: " + msg +"\n");
                byte[] encrypted = encrypt(msg, clientServerKey);
                out.write(encrypted);
                byte[] message = new byte[encrypted.length];
                in.read(message);
                String decrypted = decrypt(message, serverClientKey);
                System.out.println("Server returned cleartext: " + decrypted + "\n");
                count+=1;
                if(count >=countNum){
                    System.out.println("Updating session key...\n");
                    count = 0 ;
                    updateSessionKey();
                }else{
                    System.out.println("Update session key after...." + String.valueOf(countNum-count) + "\n");
                }
            } else {
                System.out.println("WRONG MASTER KEY!");
            }
        } catch (IOException | InvalidKeySpecException e) {
            System.out.println("Error when initializing connection: " + e.getMessage() + "\n");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private void updateSessionKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        SecretKey newMasterKey = generateRandomMasterKey();

        sendMasterKey(newMasterKey);

        clientServerKey = deriveKey("client-server", newMasterKey);
        serverClientKey = deriveKey("server-client", newMasterKey);

        System.out.println("Session key updated!\n");
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
    private static Set<ByteBuffer> seenNonces = new HashSet<>();
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
            throw new RuntimeException("Nonce has been used before");
        }
        else{
            System.out.println("Nonce is valid, process to decryption...\n");
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
        EchoClient2 client = new EchoClient2();
        int count = Integer.parseInt(args[0]);
        client.loadClientKeysFromKeystore("badpassword");
        client.loadServerKeysFromKeystore("badpassword");
        client.startConnection("127.0.0.1", 4444,  "12345678",count);
        client.startConnection("127.0.0.1", 4444,  "ABCDEFGH",count);
        client.startConnection("127.0.0.1", 4444,  "87654321",count);
        client.startConnection("127.0.0.1", 4444,  "HGFEDCBA",count);

    }
}