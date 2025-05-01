package UPS.security2FAC.Controller;

import UPS.security2FAC.Entity.DTO.Login;
import UPS.security2FAC.Entity.DTO.ResponseDTO;
import UPS.security2FAC.Entity.DTO.User;
import UPS.security2FAC.Entity.DTO.Verificar;
import UPS.security2FAC.Services.*;
import UPS.security2FAC.Utils.Constantes;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UsuarioService usuarioService;
    private final TOTPService totpService;
    private final EmailService emailService;
    private final Codigo2FAServiceEmail codigo2FAService;
    private final TwoFactorSMS smstwoFactorAuthService;

    @PostMapping("/registro")
    public ResponseEntity<ResponseDTO> registrar(@RequestBody User u) {

        if((u.getUsername() == null || u.getUsername().isEmpty() ) || (u.getPassword() == null || u.getPassword().isEmpty()))
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.VALID_USR_PWD, "Bad Request"));
        var usuarioOpt = usuarioService.buscar(u.getUsername());
        if (usuarioOpt.isPresent())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USUARIO_EXISTE, "Bad Request"));
        if(!usuarioService.isPasswordValid(u.getPassword()))
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.PASSWORD_INVALID, "Bad Request"));

        usuarioService.registrar(u);


        return ResponseEntity.ok(new ResponseDTO("201",Constantes.USUARIO_OK, "0"));
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO> login(@RequestBody Login login) throws Exception {
        var usuarioOpt = usuarioService.login(login.getUsername(), login.getPassword());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.CREDENCIALES_INVALIDAS, "Bad Request"));

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USUARIO_BLOQUEADO, "Bad Request"));

        switch (usuario.getTipoAuth()) {
            case "EMAIL":
                String codigo = codigo2FAService.generarCodigo(login.getUsername());
                emailService.enviarCodigo(usuario.getEmail(), codigo);
                return ResponseEntity.ok(new ResponseDTO("200", Constantes.EMAIL_OK + usuarioService.obfuscateEmail(usuario.getEmail()), "Solicitud procesada con éxito"));
            case "SMS":
                String idSMS = smstwoFactorAuthService.sendSMS(usuario.getTelefono());
                if (!idSMS.isEmpty())
                {
                    usuarioService.guardarIDSms(usuario, idSMS);
                    return ResponseEntity.ok(new ResponseDTO("200", Constantes.SMS_OK, "Solicitud procesada con éxito"));
                }
                else
                    return ResponseEntity.ok(new ResponseDTO("400", Constantes.EMAIL_ERROR, "Bad Request"));
            default:
                break;
        }
        if (usuario.isGauth())
        {
            if (!usuario.isTiene2FA()) {
                String secret = totpService.generarClaveSecreta();
                usuarioService.activar2FA(usuario, secret);
                String qr = totpService.procesoDeSetup(login.getUsername(),"AppUPS",  secret);
                return ResponseEntity.ok(new ResponseDTO("200", Constantes.AUTH_OK + qr, "Solicitud procesada con éxito"));
            } else {
                return ResponseEntity.ok(new ResponseDTO("200", Constantes.AUTH_OK_REG, "Solicitud procesada con éxito"));
            }
        }
        return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_NO_ENCONTRADO, "Bad Request"));
    }

    @PostMapping("/verificar-2fa")
    public ResponseEntity<ResponseDTO> verificar(@RequestBody Verificar data,
                                            HttpServletRequest request) throws Exception {
        boolean valido = false;
        var usuarioOpt = usuarioService.buscar(data.getUsername());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_NO_ENCONTRADO, "Bad Request"));

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_BLOQUEADO, "Bad Request"));

        switch (usuario.getTipoAuth()) {
            case "EMAIL":
                valido = codigo2FAService.verificarCodigo(data.getUsername(), data.getCodigo());
                break;
            case "SMS":
                valido = Boolean.parseBoolean(smstwoFactorAuthService.verifyOtp(usuario.getIdSMS(),data.getCodigo()));
                break;
            default:
                break;
        }
        if(usuario.isGauth())
        {
            String secretDescifrada = totpService.descifrar(usuario.getSecret2FA());
            valido = totpService.verificarCodigo(secretDescifrada, Integer.parseInt(data.getCodigo()));
        }

        usuarioService.registrarAuditoria(data.getUsername(), valido, request.getRemoteAddr());

        if (valido) {
            usuario.setIntentosFallidos(0);
            if (data.isRecordar()) {
                String token = totpService.generarTokenRecordado();
                usuarioService.recordarDispositivo(data.getUsername(), token);
                return ResponseEntity.ok(new ResponseDTO("200", Constantes.ACCESO_OK + token, "Solicitud procesada con éxito"));
            }
            return ResponseEntity.ok(new ResponseDTO("200", Constantes.ACCESO_OK_DOS, "Solicitud procesada con éxito"));
        } else {
            usuario.setIntentosFallidos(usuario.getIntentosFallidos() + 1);
            if (usuario.getIntentosFallidos() >= 5) {
                usuario.setBloqueado(true);
            }
            usuarioService.registrarIntentos(usuario);
            return ResponseEntity.ok(new ResponseDTO("200", Constantes.ACCESO_ERROR, "Solicitud procesada con éxito"));
        }
    }
}
