package UPS.security2FAC.Repository;

import UPS.security2FAC.Entity.DispositivoRecordado;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DispositivoRecordadoRepository extends JpaRepository<DispositivoRecordado, Long> {
    Optional<DispositivoRecordado> findByToken(String token);
}
