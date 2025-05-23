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
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.VALID_USR_PWD,false, true));
        var usuarioOpt = usuarioService.buscar(u.getUsername());
        if (usuarioOpt.isPresent())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USUARIO_EXISTE, false, true));
        if(!usuarioService.isPasswordValid(u.getPassword()))
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.PASSWORD_INVALID, false, true));
        usuarioService.registrar(u);
        return ResponseEntity.ok(new ResponseDTO("201",Constantes.USUARIO_OK, false, false));
    }

    @PostMapping("/updateUsr")
    public ResponseEntity<ResponseDTO> updateUser(@RequestBody User u) {
        var usuarioOpt = usuarioService.login(u.getUsername(), u.getPassword());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.CREDENCIALES_INVALIDAS,false, true));

        var usuario = usuarioOpt.get();
        usuario.setTipoAuth(u.getTipo2FA());
        usuario.setEmail(u.getEmail());
        usuario.setTelefono(u.getTelefono());
        usuario.setGauth (u.isGauth());
        usuarioService.registrarIntentos(usuario);
        return ResponseEntity.ok(new ResponseDTO("200", Constantes.CREDENCIALES_INVALIDAS,false, false));
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseDTO> login(@RequestBody Login login) throws Exception {
        var usuarioOpt = usuarioService.login(login.getUsername(), login.getPassword());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_NO_ENCONTRADO,false, true));

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USUARIO_BLOQUEADO,usuario.isTiene2FA(), true));

        if((usuario.getTipoAuth() == null || usuario.getTipoAuth().isEmpty()) || usuario.isGauth())
            return ResponseEntity.ok(new ResponseDTO("200", Constantes.DOBLE_FACT, usuario.isTiene2FA(), false));

        if (!usuario.isTiene2FA())
        {
            switch (usuario.getTipoAuth().toUpperCase()) {
                case "EMAIL":
                    String codigo = codigo2FAService.generarCodigo(login.getUsername());
                    emailService.enviarCodigo(usuario.getEmail(), codigo);
                    usuarioService.updateDobleFactor(usuario, true);
                    return ResponseEntity.ok(new ResponseDTO("200", Constantes.EMAIL_OK + usuarioService.obfuscateEmail(usuario.getEmail()),usuario.isTiene2FA(), false));
                case "SMS":
                    String idSMS = smstwoFactorAuthService.sendSMS(usuario.getTelefono());
                    if (!idSMS.isEmpty())
                    {
                        usuarioService.guardarIDSms(usuario, idSMS);
                        usuarioService.updateDobleFactor(usuario, true);
                        return ResponseEntity.ok(new ResponseDTO("200", Constantes.SMS_OK, usuario.isTiene2FA(),  false));
                    }
                    else
                    {
                        usuarioService.updateDobleFactor(usuario, false);
                        return ResponseEntity.ok(new ResponseDTO("400", Constantes.EMAIL_ERROR, usuario.isTiene2FA(), true));
                    }

                default:
                    break;
            }
            if (usuario.isGauth() && (usuario.getSecret2FA() == null || usuario.getSecret2FA().isEmpty()))
            {
                String secret = totpService.generarClaveSecreta();
                usuarioService.activar2FA(usuario, secret);
                String qr = totpService.procesoDeSetup(login.getUsername(),"Seguridad UPS",  secret);
                return ResponseEntity.ok(new ResponseDTO("200", qr, usuario.isTiene2FA(), false));
            }
            else
                return ResponseEntity.ok(new ResponseDTO("200", "Ingreso el codigo generado en Google Authenticator", usuario.isTiene2FA(), false));
        }
        return ResponseEntity.ok(new ResponseDTO("200", usuario.getTipoAuth(), usuario.isTiene2FA(), false));
    }

    @PostMapping("/FactorGenerate")
    public ResponseEntity<ResponseDTO> FactorGenerate(@RequestBody Login login) throws Exception {
        var usuarioOpt = usuarioService.login(login.getUsername(), login.getPassword());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.CREDENCIALES_INVALIDAS, false, true));

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USUARIO_BLOQUEADO, usuario.isTiene2FA(), true));

        switch (usuario.getTipoAuth().toUpperCase()) {
            case "EMAIL":
                String codigo = codigo2FAService.generarCodigo(login.getUsername());
                emailService.enviarCodigo(usuario.getEmail(), codigo);
                usuarioService.updateDobleFactor(usuario, true);
                return ResponseEntity.ok(new ResponseDTO("200", "email", usuario.isTiene2FA(), false));
            case "SMS":
                String idSMS = smstwoFactorAuthService.sendSMS(usuario.getTelefono());
                if (!idSMS.isEmpty())
                {
                    usuarioService.guardarIDSms(usuario, idSMS);
                    usuarioService.updateDobleFactor(usuario, true);
                    return ResponseEntity.ok(new ResponseDTO("200", "sms", usuario.isTiene2FA(), false));
                }
                else
                {
                    usuarioService.updateDobleFactor(usuario, false);
                    return ResponseEntity.ok(new ResponseDTO("400", Constantes.EMAIL_ERROR, usuario.isTiene2FA(), true));
                }
            default:
                break;
        }
        if (usuario.isGauth() && null == usuario.getSecret2FA())
        {
            String secret = totpService.generarClaveSecreta();
            usuarioService.activar2FA(usuario, secret);
            String qr = totpService.procesoDeSetup(login.getUsername(),"Seguridad UPS",  secret);
            return ResponseEntity.ok(new ResponseDTO("200", qr, usuario.isTiene2FA(), false));
        } else if (usuario.isGauth() && !usuario.getSecret2FA().isEmpty()) {
            return ResponseEntity.ok(new ResponseDTO("200", "app", usuario.isTiene2FA(), false));
        }
        return ResponseEntity.ok(new ResponseDTO("400", Constantes.AUTH_NO_EN, usuario.isTiene2FA(),  true));
    }


    @PostMapping("/verificar-2fa")
    public ResponseEntity<ResponseDTO> verificar(@RequestBody Verificar data,
                                            HttpServletRequest request) throws Exception {
        boolean valido = false;
        var usuarioOpt = usuarioService.buscar(data.getUsername());
        if (usuarioOpt.isEmpty())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_NO_ENCONTRADO, false, true));

        var usuario = usuarioOpt.get();
        if (usuario.isBloqueado())
            return ResponseEntity.ok(new ResponseDTO("400", Constantes.USR_BLOQUEADO, usuario.isTiene2FA(), true));

        switch (usuario.getTipoAuth().toUpperCase()) {
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
                return ResponseEntity.ok(new ResponseDTO("200", Constantes.ACCESO_OK + token, usuario.isTiene2FA(), false));
            }
            return ResponseEntity.ok(new ResponseDTO("200", Constantes.ACCESO_OK_DOS, usuario.isTiene2FA(), false));
        } else {
            usuario.setIntentosFallidos(usuario.getIntentosFallidos() + 1);
            if (usuario.getIntentosFallidos() >= 5) {
                usuario.setBloqueado(true);
            }
            usuarioService.registrarIntentos(usuario);
            return ResponseEntity.ok(new ResponseDTO("401", Constantes.ACCESO_ERROR, usuario.isTiene2FA(), true));
        }
    }
}
