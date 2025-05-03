package UPS.security2FAC.Services;


import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;


@Service
public class TOTPService {

    private static final Logger log = LoggerFactory.getLogger(TOTPService.class);
    private final GoogleAuthenticator gAuth;
    private final String claveSecreta;

    public TOTPService(@Value("${password.salt}") String claveSecreta,
                       GoogleAuthenticator googleAuthenticator) {
        this.claveSecreta = claveSecreta;
        this.gAuth = googleAuthenticator;
    }

    public String generarClaveSecreta() {
        return gAuth.createCredentials().getKey();
    }

    public String procesoDeSetup(String usuario, String issuer, String secret) {
        GoogleAuthenticatorKey.Builder keyBuilderDummy = new GoogleAuthenticatorKey.Builder(secret);
        GoogleAuthenticatorKey credentials = keyBuilderDummy.build();
        return generarQR(usuario, credentials, issuer);
    }

    public String generarQR(String usuario, GoogleAuthenticatorKey credentials, String issuer) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(issuer, usuario, credentials);
    }

    public boolean verificarCodigo(String secret, int codigo) {
        return gAuth.authorize(secret, codigo);
    }

    public String cifrar(String texto) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(claveSecreta.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(texto.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Error al cifrar", e);
        }
    }

    public String descifrar(String textoCifrado) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(claveSecreta.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(textoCifrado)));
        } catch (Exception e) {
            throw new RuntimeException("Error al descifrar", e);
        }
    }

    public String generarTokenRecordado() {
        return UUID.randomUUID().toString();
    }

}
