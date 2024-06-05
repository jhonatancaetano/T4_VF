import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class RestorePrivateKey{
    public static void main(String[] args) {
        try {
            // Caminho para o arquivo da chave privada criptografada e a senha
            File encryptedKeyFile = new File("/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Keys/user04-pkcs8-aes.pem");
            String secretPhrase = "user04";

            // Restaura a chave privada
            PrivateKey privateKey = restoreKey(encryptedKeyFile, secretPhrase);

            // Exibe a chave privada
            System.out.println("Chave Privada: " + privateKey.toString());
            System.out.println("Chave Privada (Base64): " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static PrivateKey restoreKey(File encryptedKeyFile, String secretPhrase) throws Exception {
        byte[] decryptedPrivateKey = null;
        try {
            byte[] encryptedKeyBytes = readFileBytes(encryptedKeyFile);

            // Geração da chave simétrica a partir da senha
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(secretPhrase.getBytes(StandardCharsets.UTF_8));
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, secureRandom);
            SecretKey symmetricKey = keyGen.generateKey();

            // Decriptar a chave privada
            decryptedPrivateKey = decryptData("AES/ECB/PKCS5Padding", encryptedKeyBytes, symmetricKey);
            String privateKeyPem = new String(decryptedPrivateKey, StandardCharsets.UTF_8);

            // Limpeza da string da chave privada
            privateKeyPem = privateKeyPem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            // Decodificação Base64
            decryptedPrivateKey = Base64.getDecoder().decode(privateKeyPem);

            Arrays.fill(encryptedKeyBytes, (byte) 0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 BadPaddingException | IllegalBlockSizeException | IOException e) {
            System.err.println("Erro durante a restauração da chave privada");
            e.printStackTrace();
            throw new Exception("Erro na restauração da chave privada", e);
        }

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedPrivateKey);
        Arrays.fill(decryptedPrivateKey, (byte) 0);

        PrivateKey privateKey = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.err.println("Erro ao gerar chave privada");
            e.printStackTrace();
            throw new Exception("Erro ao gerar chave privada", e);
        }

        return privateKey;
    }

    private static byte[] readFileBytes(File file) throws IOException {
        byte[] fileData = new byte[(int) file.length()];
        try (FileInputStream inputStream = new FileInputStream(file)) {
            inputStream.read(fileData);
        }
        return fileData;
    }

    private static byte[] decryptData(String algorithm, byte[] data, Key key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
