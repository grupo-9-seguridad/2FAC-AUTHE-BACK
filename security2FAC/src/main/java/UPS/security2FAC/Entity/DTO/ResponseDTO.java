package UPS.security2FAC.Entity.DTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResponseDTO {
    private String status;
    private String message;
    private Boolean tiene2FA;
    private Boolean hasError;
}
