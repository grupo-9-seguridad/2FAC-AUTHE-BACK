package UPS.security2FAC.Configuration;

import UPS.security2FAC.Services.EmailService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class EmailRunner implements ApplicationRunner {

    private final EmailService emailService;

    public EmailRunner(EmailService emailService) {
        this.emailService = emailService;
    }

    @Override
    public void run(ApplicationArguments args) {
        emailService.enviarCodigo("wilmercaiza@gmail.com", "12346");
    }

}
