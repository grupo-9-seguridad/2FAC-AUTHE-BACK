package UPS.security2FAC.Services;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class Codigo2FAServiceEmail {
    private final Map<String, String> codigosPorUsuario = new ConcurrentHashMap<>();
    private final Random random = new Random();

    public String generarCodigo(String username) {
        String codigo = String.format("%06d", random.nextInt(999999));
        codigosPorUsuario.put(username, codigo);
        return codigo;
    }

    public boolean verificarCodigo(String username, String codigoIngresado) {
        String codigoCorrecto = codigosPorUsuario.get(username);
        if (codigoCorrecto != null && codigoCorrecto.equals(codigoIngresado)) {
            codigosPorUsuario.remove(username); // usar una sola vez
            return true;
        }
        return false;
    }
}
