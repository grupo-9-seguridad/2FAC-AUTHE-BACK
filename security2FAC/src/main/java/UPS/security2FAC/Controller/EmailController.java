package UPS.security2FAC.Controller;

import UPS.security2FAC.Services.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/email")
@RequiredArgsConstructor
public class EmailController {

    private final EmailService emailService;

    @PostMapping
    public ResponseEntity<?> run(@RequestParam String email, @RequestParam String code) {
        emailService.enviarCodigo(email, code);
        return ResponseEntity.ok().build();
    }

}
