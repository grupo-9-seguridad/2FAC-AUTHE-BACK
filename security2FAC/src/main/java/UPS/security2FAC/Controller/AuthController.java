package UPS.security2FAC.Controller;

import UPS.security2FAC.Entity.DTO.Login;
import UPS.security2FAC.Entity.DTO.User;
import UPS.security2FAC.Entity.DTO.Verificar;
import UPS.security2FAC.Services.Codigo2FAServiceEmail;
import UPS.security2FAC.Services.EmailService;
import UPS.security2FAC.Services.TOTPService;
import UPS.security2FAC.Services.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UsuarioService usuarioService;
    private final TOTPService totpService;
    private final EmailService emailService;
    private final Codigo2FAServiceEmail codigo2FAService;

    @PostMapping("/registro")
    public ResponseEntity<String> registrar(@RequestBody User u) {

        if((u.getUsername() == null || u.getUsername().isEmpty() ) || (u.getPassword() == null || u.getPassword().isEmpty()))
            ResponseEntity.status(401).body("Ingrese el usuario o contrasena");
        var usuarioOpt = usuarioService.buscar(u.getUsername());
        if (usuarioOpt.isPresent())
            return ResponseEntity.status(401).body("Usuario ya existe");
        usuarioService.registrar(u);

        return ResponseEntity.ok("Usuario registrado exitosamente.");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Login login) {
        var usuarioOpt = usuarioService.login(login.getUsername(), login.getPassword());
        if (usuarioOpt.isEmpty()) return ResponseEntity.status(401).body("Credenciales inválidas");

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado()) return ResponseEntity.status(403).body("Usuario bloqueado");

        switch (usuario.getTipoAuth()) {
            case "EMAIL":
                String codigo = codigo2FAService.generarCodigo(login.getUsername());
                emailService.enviarCodigo(usuario.getEmail(), codigo);
                return ResponseEntity.ok("Ingresa el código de verificación enviado a : " + usuarioService.obfuscateEmail(usuario.getEmail()));
            case "SMS":
                // Código para autenticación por SMS
                break;
            default:
                // Manejo de casos no contemplados (opcional)
                break;
        }
        if (usuario.isGauth())
        {
            if (!usuario.isTiene2FA()) {
                String secret = totpService.generarClaveSecreta();
                usuarioService.activar2FA(usuario, secret);
                String qr = totpService.procesoDeSetup(login.getUsername(),"AppUPS",  secret);
                return ResponseEntity.ok("Escanea el código QR con Google Authenticator: " + qr);
            } else {
                return ResponseEntity.ok("Ingresa tu código de 2FA generado por tu app");
            }
        }
        return ResponseEntity.status(401).body("Usuario no encontrado");
    }

    @PostMapping("/verificar-2fa")
    public ResponseEntity<String> verificar(@RequestBody Verificar data,
                                            HttpServletRequest request) {
        boolean valido = false;
        var usuarioOpt = usuarioService.buscar(data.getUsername());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.status(404).body("Usuario no encontrado");

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.status(403).body("Usuario bloqueado");

        switch (usuario.getTipoAuth()) {
            case "EMAIL":
                valido = codigo2FAService.verificarCodigo(data.getUsername(), String.valueOf(data.getCodigo()));
                break;
            case "SMS":
                // Código para autenticación por SMS
                break;
            default:
                // Manejo de casos no contemplados (opcional)
                break;
        }
        if(usuario.isGauth())
        {
            String secretDescifrada = totpService.descifrar(usuario.getSecret2FA());
            valido = totpService.verificarCodigo(secretDescifrada, data.getCodigo());
        }

        usuarioService.registrarAuditoria(data.getUsername(), valido, request.getRemoteAddr());

        if (valido) {
            usuario.setIntentosFallidos(0);
            if (data.isRecordar()) {
                String token = totpService.generarTokenRecordado();
                usuarioService.recordarDispositivo(data.getUsername(), token);
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
