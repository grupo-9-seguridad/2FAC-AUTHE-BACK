package UPS.security2FAC.Controller;

import UPS.security2FAC.Services.TOTPService;
import UPS.security2FAC.Services.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UsuarioService usuarioService;
    private final TOTPService totpService;

    @PostMapping("/registro")
    public String registrar(@RequestParam String username, @RequestParam String password) {

        if((username == null || username.isEmpty() ) || (password == null || password.isEmpty()))
            return "Ingrese el usuario o contrasena";
        var usuarioOpt = usuarioService.buscar(username);
        if (usuarioOpt.isPresent())
            return "Usuario ya existe";

        usuarioService.registrar(username, password);
        return "Usuario registrado";
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        var usuarioOpt = usuarioService.login(username, password);
        if (usuarioOpt.isEmpty()) return ResponseEntity.status(401).body("Credenciales inválidas");

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado()) return ResponseEntity.status(403).body("Usuario bloqueado");

        if (!usuario.isTiene2FA()) {
            String secret = totpService.generarClaveSecreta();
            usuarioService.activar2FA(usuario, secret);
            String qr = totpService.procesoDeSetup(username,"AppUPS",  secret);
            return ResponseEntity.ok("Escanea el código QR con Google Authenticator: " + qr);
        } else {
            return ResponseEntity.ok("Ingresa tu código de 2FA generado por tu app");
        }
    }

    @PostMapping("/verificar-2fa")
    public ResponseEntity<String> verificar(@RequestParam String username, @RequestParam int codigo,
                                            @RequestParam(required = false) boolean recordar,
                                            HttpServletRequest request) {
        var usuarioOpt = usuarioService.buscar(username);
        if (usuarioOpt.isEmpty())
            return ResponseEntity.status(404).body("Usuario no encontrado");

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.status(403).body("Usuario bloqueado");

        String secretDescifrada = totpService.descifrar(usuario.getSecret2FA());
        boolean valido = totpService.verificarCodigo(secretDescifrada, codigo);

        usuarioService.registrarAuditoria(username, valido, request.getRemoteAddr());

        if (valido) {
            usuario.setIntentosFallidos(0);
            if (recordar) {
                String token = totpService.generarTokenRecordado();
                usuarioService.recordarDispositivo(username, token);
                return ResponseEntity.ok("Acceso concedido ✅\nToken de dispositivo: " + token);
            }
            return ResponseEntity.ok("Acceso concedido ✅");
        } else {
            usuario.setIntentosFallidos(usuario.getIntentosFallidos() + 1);
            if (usuario.getIntentosFallidos() >= 5) {
                usuario.setBloqueado(true);
            }
            usuarioService.registrarIntentos(usuario);
            return ResponseEntity.status(401).body("Código inválido ❌");
        }
    }
}
