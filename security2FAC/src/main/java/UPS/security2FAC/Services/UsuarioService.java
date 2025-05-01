package UPS.security2FAC.Services;


import UPS.security2FAC.Entity.AuditoriaAcceso;
import UPS.security2FAC.Entity.DTO.User;
import UPS.security2FAC.Entity.DispositivoRecordado;
import UPS.security2FAC.Entity.Usuario;
import UPS.security2FAC.Repository.AuditoriaAccesoRepository;
import UPS.security2FAC.Repository.DispositivoRecordadoRepository;
import UPS.security2FAC.Repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class UsuarioService {
    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;
    private final TOTPService totpService;
    private final AuditoriaAccesoRepository auditoriaRepo;
    private final DispositivoRecordadoRepository dispositivoRepo;

    public Usuario registrar(User usr) {
        Usuario u = Usuario.builder()
                .username(usr.getUsername())
                .password(encoder.encode(usr.getPassword()))
                .telefono(usr.getTelefono())
                .email(usr.getEmail())
                .gauth(usr.isGauth())
                .tipoAuth(usr.getTipo2FA())
                .tiene2FA(false)
                .bloqueado(false)
                .intentosFallidos(0)
                .build();
        return repo.save(u);
    }

    public Optional<Usuario> login(String username, String password) {
        return repo.findByUsername(username)
                .filter(u -> encoder.matches(password, u.getPassword()));
    }

    public Usuario activar2FA(Usuario u, String secret) {
        u.setSecret2FA(totpService.cifrar(secret));
        u.setTiene2FA(true);
        return repo.save(u);
    }
    public Usuario guardarIDSms(Usuario u, String secret) {
        u.setIdSMS(secret);
        return repo.save(u);
    }

    public void registrarAuditoria(String username, boolean exito, String ip) {
        auditoriaRepo.save(AuditoriaAcceso.builder()
                .username(username)
                .exito(exito)
                .ip(ip)
                .fecha(LocalDateTime.now())
                .build());
    }

    public Optional<DispositivoRecordado> verificarDispositivo(String token) {
        return dispositivoRepo.findByToken(token)
                .filter(d -> d.getExpiracion().isAfter(LocalDateTime.now()));
    }

    public void recordarDispositivo(String username, String token) {
        dispositivoRepo.save(DispositivoRecordado.builder()
                .username(username)
                .token(token)
                .expiracion(LocalDateTime.now().plusDays(30))
                .build());
    }

    public Optional<Usuario> buscar(String username) {
        return repo.findByUsername(username);
    }

    public void registrarIntentos(Usuario usr){
        repo.save(usr);
    }

    public String obfuscateEmail(String email) {
        if (email == null || email.isEmpty()) {
            return email;
        }
        int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email;
        }
        String localPart = email.substring(0, atIndex);
        String domainPart = email.substring(atIndex);
        if (localPart.length() <= 2) {
            return localPart.charAt(0) + "***" + domainPart;
        } else {
            return localPart.charAt(0) + "***" + localPart.charAt(localPart.length() - 1) + domainPart;
        }
    }

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])" +           // al menos un dígito
                    "(?=.*[a-z])" +            // al menos una minúscula
                    "(?=.*[A-Z])" +            // al menos una mayúscula
                    "(?=.*[@#$%^&+=!])" +      // al menos un caracter especial
                    "(?=\\S+$)" +              // sin espacios
                    ".{8,}$"                   // mínimo 8 caracteres
    );

    public boolean isPasswordValid(String password) {
        if (password == null) return false;
        return PASSWORD_PATTERN.matcher(password).matches();
    }

    public static String getPolicyDescription() {
        return "";
    }
}
