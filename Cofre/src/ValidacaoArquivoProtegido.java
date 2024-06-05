import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;

public class ValidacaoArquivoProtegido {

    public static void main(String[] args) {
        try {
            // Caminho para o arquivo da chave privada criptografada e a frase secreta
            File keyFile = new File("/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Keys/user04-pkcs8-aes.pem");
            String fraseSecreta = "user04";

            // Caminho do arquivo do certificado digital
            String certPath = "/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Keys/user04-x509.crt";

            // Carregar os dados dos arquivos .enc, .env e .asd
            byte[] indexEnc = Files.readAllBytes(new File("/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Files/XXYYZZ03.enc").toPath());
            byte[] indexEnv = Files.readAllBytes(new File("/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Files/XXYYZZ03.env").toPath());
            byte[] indexAsd = Files.readAllBytes(new File("/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Files/XXYYZZ03.asd").toPath());

            // Restaura a chave privada
            PrivateKey chavePrivada = RestorePrivateKey.restoreKey(keyFile, fraseSecreta);

            // Restaura a chave pública
            PublicKey chavePublica = RestorePublicKey.restorePublicKey(certPath);

            // Decriptar o envelope para obter a semente da chave simétrica
            byte[] semente = decriptarEnvelope(indexEnv, chavePrivada);

            if (semente == null) {
                System.err.println("Erro: Chave incorreta ou problema durante a decriptação do envelope.");
                return;
            }

            // Gera a chave simétrica a partir da semente
            SecretKey chaveSimetrica = gerarChaveSimetrica(semente);

            // Imprimir a chave simetrica em hexadecimal
            System.out.println("Chave Simétrica: " + bytesToHex(chaveSimetrica.getEncoded()));

            // Decripta o arquivo index
            byte[] index = decriptarArquivo(indexEnc, chaveSimetrica);

            if (index != null) { // Verifica se a descriptografia foi bem-sucedida
                // Verifica a assinatura do arquivo index
                boolean assinaturaValida = verificarAssinatura(index, indexAsd, chavePublica);

                if (assinaturaValida) {
                    System.out.println("Assinatura válida. O arquivo é autêntico.");
                } else {
                    System.out.println("Assinatura inválida. O arquivo pode ter sido alterado.");
                }
            } else {
                System.err.println("Erro: Problema durante a descriptografia do arquivo index.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] decriptarEnvelope(byte[] envelope, PrivateKey chavePrivada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        return cipher.doFinal(envelope);
    }

    private static SecretKey gerarChaveSimetrica(byte[] semente) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] chave = digest.digest(semente);
            return new SecretKeySpec(Arrays.copyOf(chave, 16), "AES"); // Usa apenas os primeiros 16 bytes para AES-128
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] decriptarArquivo(byte[] criptograma, SecretKey chaveSimetrica) {
        byte[] iv = Arrays.copyOfRange(criptograma, 0, 16); // Extrai o IV do criptograma
        byte[] encryptedData = Arrays.copyOfRange(criptograma, 16, criptograma.length); // Extrai os dados criptografados

        try {
            System.out.println("IV: " + bytesToHex(iv)); // Print do IV
            System.out.println("Encrypted Data Length: " + encryptedData.length); // Print do tamanho dos dados criptografados

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParams = new IvParameterSpec(iv); // Cria o parâmetro IV
            System.out.println("Chave Simétrica (Hex): " + bytesToHex(chaveSimetrica.getEncoded())); // Print da chave simétrica em hexadecimal
            cipher.init(Cipher.DECRYPT_MODE, chaveSimetrica, ivParams); // Inicializa o modo de descriptografia com a chave e o IV

            byte[] decryptedData = cipher.doFinal(encryptedData); // Descriptografa os dados

            // Debugging: Print dos dados descriptografados
            System.out.println("Decrypted Data: " + new String(decryptedData));

            return decryptedData;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    private static boolean verificarAssinatura(byte[] dados, byte[] assinatura, PublicKey chavePublica) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(chavePublica);
        signature.update(dados);
        return signature.verify(assinatura);
    }

}
