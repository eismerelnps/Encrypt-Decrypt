/*En este ejemplo, se usa AES en modo CBC con relleno PKCS5 para cifrar y descifrar una cadena de texto.
 Además, se usa PBKDF2 con HmacSHA256 para generar una clave secreta a partir de una contraseña proporcionada
  por el usuario.*?
 */
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        char[] password ;
        System.out.println("Type your password to encrypt: ");
        String inputPassword = new Scanner(System.in).nextLine();
        String passwordEncrypted;
        String passwordDecrypted;
        try {
            System.out.println("Type your encrypting-decrypting pin  : ");
            password = new Scanner(System.in).nextLine().toCharArray();
            System.out.println("Password encrypted: "+EncryptionExample.encrypt(inputPassword, password ));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        try {
            System.out.println("Type your encrypting-decrypting pin : ");
            password = new Scanner(System.in).nextLine().toCharArray();
            System.out.println("Type your encrypted text for decrypting");
            passwordEncrypted = new Scanner(System.in).nextLine();
            passwordDecrypted =  EncryptionExample.decrypt(passwordEncrypted, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        System.out.println("Password: "+inputPassword);
        System.out.println("Password decrypted: "+passwordDecrypted);
    }


    public class EncryptionExample {

        private static final String encryptionAlgorithm = "AES/CBC/PKCS5Padding";
        private static final String secretKeyAlgorithm = "AES";
        private static final String secretKeyFactoryAlgorithm = "PBKDF2WithHmacSHA256";

        public static String encrypt(String plainText, char[] password) throws Exception {
            byte[] salt = new byte[16];
            IvParameterSpec iv = new IvParameterSpec(salt);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyFactoryAlgorithm);
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), secretKeyAlgorithm);

            Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secret, iv);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        }

        public static String decrypt(String encryptedText, char[] password) throws Exception {
            byte[] decrypted = null;
            try {
                byte[] salt = new byte[16];
                IvParameterSpec iv = new IvParameterSpec(salt);
                SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyFactoryAlgorithm);
                KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKey secret = new SecretKeySpec(tmp.getEncoded(), secretKeyAlgorithm);

                Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
                cipher.init(Cipher.DECRYPT_MODE, secret, iv);
                byte[] decodedEncryptedText = Base64.getDecoder().decode(encryptedText);
                 decrypted = cipher.doFinal(decodedEncryptedText);
            } catch (IllegalBlockSizeException exception) {
                String Message = "Ha ocurrido un error al decifrar su contraseña, verifique que ha introducido correctamente su contrasena encryptada";
                return Message;
            }catch (BadPaddingException exception){
                String Message = "Ha ocurrido un error al decifrar su contraseña, verifique que ha introducido correctamente su contraseña de encriptamiento";
                return Message;
            }

                return new String(decrypted, StandardCharsets.UTF_8);

        }
    }

}