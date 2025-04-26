package UPS.security2FAC.Entity.DTO;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Verificar {
    private String username;
    private Integer codigo;
    private boolean recordar;
}
