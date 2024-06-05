import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PublicKey;

public class RestorePublicKey {
    public static PublicKey restorePublicKey(String certPath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(certPath);
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
        fis.close();
        return certificate.getPublicKey();
    }

    public static void main(String[] args) {
        try {
            // Caminho do arquivo do certificado digital
            String certPath = "/Users/jhonatan.caetano/Documents/Trabalho4/Cofre/SafeVault/Keys/user04-x509.crt";

            // Restaura a chave pública do certificado
            PublicKey publicKey = restorePublicKey(certPath);

            // Exibe a chave pública
            System.out.println("Chave Pública: " + publicKey.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

