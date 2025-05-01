package UPS.security2FAC.Services;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class TwoFactorSMS {

    private final InfobipSmsService smsService;

    public String sendSMS(String phoneNumber) throws Exception {
        return smsService.sendSms(phoneNumber, "Tu código de verificación es: ");
    }

    public String verifyOtp(String idOtp, String otp) throws Exception {
        return smsService.verifyOTP(idOtp, otp);
    }

}
