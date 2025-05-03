workspace "Sistema de Autenticación 2FA" {

  model {
    user = person "Usuario" {
      description "Usuario final que necesita autenticarse usando 2FA"
    }

    system = softwareSystem "Sistema de Autenticación 2FA" {
      description "Sistema que proporciona autenticación en dos pasos usando email, SMS o apps como Google Authenticator."

      user -> system "Se autentica y usa 2FA"

      frontend = container "Frontend (React)" {
        technology "React"
        description "Aplicación web que permite al usuario autenticarse y seleccionar el método de 2FA"
      }

      backend = container "Backend (Spring Boot)" {
        technology "Java + Spring Boot"
        description "API REST que maneja login, generación y validación de 2FA"
      }

      emailService = container "Email Service (SMTP)" {
        technology "SMTP"
        description "Servicio externo para el envío de códigos por correo electrónico"
      }

      smsGateway = container "SMS Gateway" {
        technology "Twilio u otro"
        description "Servicio externo para el envío de códigos por SMS"
      }

      authenticatorApp = container "Authenticator App" {
        technology "Google Authenticator u otra"
        description "Aplicación que genera códigos TOTP"
      }

      database = container "Base de Datos" {
        technology "PostgreSQL"
        description "Almacena usuarios, secretos TOTP, registros de 2FA, etc."
      }

      user -> frontend "Usa la aplicación web"
      frontend -> backend "Consume APIs REST"
      backend -> emailService "Envía código por email"
      backend -> smsGateway "Envía código por SMS"
      backend -> authenticatorApp "Genera y valida códigos TOTP"
      backend -> database "Lee/escribe datos de autenticación"
    }
  }

  views {
    systemContext system {
      include *
      autolayout lr
      title "Contexto - Sistema de Autenticación 2FA"
    }

    container system {
      include *
      autolayout lr
      title "Contenedores - Sistema de Autenticación 2FA"
    }

    theme default
  }

  
}

