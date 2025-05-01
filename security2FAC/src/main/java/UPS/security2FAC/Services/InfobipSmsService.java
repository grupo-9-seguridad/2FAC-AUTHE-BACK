package UPS.security2FAC.Services;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.AllArgsConstructor;
import okhttp3.*;
import okhttp3.MediaType;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class InfobipSmsService {

    public String sendSms(String phoneNumber, String messageId) throws Exception {
        String messageIdSend = mensajeID("E08775078446682EA608428BA2175BF2", messageId);
        if(!messageIdSend.isEmpty())
        {
            OkHttpClient client = new OkHttpClient().newBuilder()
                    .build();
            MediaType mediaType = MediaType.parse("application/json");
            RequestBody body = RequestBody.create(mediaType, "{\"applicationId\":\"E08775078446682EA608428BA2175BF2\",\"messageId\":\""+messageIdSend+"\",\"from\":\"447491163443\",\"to\":\""+phoneNumber+"\"}");
            Request request = new Request.Builder()
                    .url("https://4ez14m.api.infobip.com/2fa/2/pin")
                    .method("POST", body)
                    .addHeader("Authorization", "App 3fa7f7e63e6c25b80414a56b1679212e-47a44b37-a533-4d41-b3aa-cd8283961e1a")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Accept", "application/json")
                    .build();

            try {
                Response response = client.newCall(request).execute();
                if (response.isSuccessful()) {
                    String responseBody = response.body().string();
                    System.out.println("Json response sendSms : " +responseBody);
                    JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
                    return jsonObject.get("pinId").getAsString();
                }
            } catch (Exception e) {
                System.err.println("Error enviando SMS: " + e.getMessage());
            }
        }
        return "";
    }

    private String mensajeID(String applicationId, String Otp) throws Exception {
        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        MediaType mediaType = MediaType.parse("application/json");
        RequestBody body = RequestBody.create(mediaType, "{\"pinType\":\"NUMERIC\",\"messageText\":\""+Otp+"\",\"pinLength\":4,\"senderId\":\"ServiceSMS\"}");
        Request request = new Request.Builder()
                .url("https://4ez14m.api.infobip.com/2fa/2/applications/"+applicationId+"/messages")
                .method("POST", body)
                .addHeader("Authorization", "App 3fa7f7e63e6c25b80414a56b1679212e-47a44b37-a533-4d41-b3aa-cd8283961e1a")
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .build();
        try {
            Response response = client.newCall(request).execute();
            if (response.isSuccessful()) {
                String responseBody = response.body().string();
                System.out.println("Json response mensajeID : " +responseBody);
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
                return jsonObject.get("messageId").getAsString();
            }
        } catch (Exception e) {
            System.err.println("Error enviando SMS: " + e.getMessage());
        }
        return "";
    }


    public String verifyOTP(String idOtp, String otp) throws Exception {

        OkHttpClient client = new OkHttpClient().newBuilder()
                .build();
        MediaType mediaType = MediaType.parse("application/json");
        RequestBody body = RequestBody.create(mediaType, "{\"pin\":\""+otp+"\"}");
        Request request = new Request.Builder()
                .url("https://4ez14m.api.infobip.com/2fa/2/pin/"+idOtp+"/verify")
                .method("POST", body)
                .addHeader("Authorization", "App 3fa7f7e63e6c25b80414a56b1679212e-47a44b37-a533-4d41-b3aa-cd8283961e1a")
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .build();
        Response response = null;
        try {
            response = client.newCall(request).execute();
            String responseBody = response.body().string();
            System.out.println("Proceso de validación: Código Enviado " +otp + " Json response: " +responseBody);
            if (response.isSuccessful()) {
                JsonObject jsonObject = JsonParser.parseString(responseBody).getAsJsonObject();
                String pinError = jsonObject.has("pinError") ? jsonObject.get("pinError").getAsString() : null;
                if (jsonObject.get("verified").getAsBoolean()) {
                    if (pinError != null) {
                        return  "false";
                    } else {
                       return "true";
                    }
                } else {
                    return "false";
                }

            }
        } catch (Exception e) {
            System.err.println("Error enviando SMS: " + e.getMessage());
        }
        finally {
            // Cerrar la respuesta para liberar los recursos
            if (response != null) {
                response.close();
            }
            }

        return "";
    }

//    private void IDAplication()
//    {
//        OkHttpClient client = new OkHttpClient().newBuilder()
//                .build();
//        MediaType mediaType = MediaType.parse("application/json");
//        RequestBody body = RequestBody.create(mediaType, "{\"name\":\"2fa test application\",\"enabled\":true,\"configuration\":{\"pinAttempts\":10,\"allowMultiplePinVerifications\":true,\"pinTimeToLive\":\"15m\",\"verifyPinLimit\":\"1/3s\",\"sendPinPerApplicationLimit\":\"100/1d\",\"sendPinPerPhoneNumberLimit\":\"10/1d\"}}");
//        Request request = new Request.Builder()
//                .url("https://4ez14m.api.infobip.com/2fa/2/applications")
//                .method("POST", body)
//                .addHeader("Authorization", "App 3fa7f7e63e6c25b80414a56b1679212e-47a44b37-a533-4d41-b3aa-cd8283961e1a")
//                .addHeader("Content-Type", "application/json")
//                .addHeader("Accept", "application/json")
//                .build();
//        try {
//            Response response = client.newCall(request).execute();
//            System.out.println("Respuesta Infobip: " + response.request() + response.body().string());
//            if (response.isSuccessful()) {
//                JsonObject jsonObject = JsonParser.parseString(response.body().string()).getAsJsonObject();
//                String applicationId = jsonObject.get("applicationId").getAsString();
//                //mensajeID(applicationId);
//            }
//        } catch (Exception e) {
//            System.err.println("Error enviando SMS: " + e.getMessage());
//        }
//    }


}
