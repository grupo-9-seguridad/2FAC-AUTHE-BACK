package UPS.security2FAC.Services;


import UPS.security2FAC.Entity.AuditoriaAcceso;
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

@Service
@RequiredArgsConstructor
public class UsuarioService {
    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;
    private final TOTPService totpService;
    private final AuditoriaAccesoRepository auditoriaRepo;
    private final DispositivoRecordadoRepository dispositivoRepo;

    public Usuario registrar(String username, String password) {
        Usuario u = Usuario.builder()
                .username(username)
                .password(encoder.encode(password))
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
}
