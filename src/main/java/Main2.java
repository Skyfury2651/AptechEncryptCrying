import org.json.simple.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Main2 {
    public static PublicKey publicKey;
    public static PrivateKey privateKey;

    public static void main(String argv[]) throws Exception {
        String sentence_to_server;
        String sentence_from_server;

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
        privateKey = (PrivateKey) keys.get("private");
        publicKey = (PublicKey) keys.get("public");


        while (true) {
            //Tạo Inputstream(từ bàn phím)
            System.out.print("Input from client: ");
            BufferedReader inFromUser =
                    new BufferedReader(new InputStreamReader(System.in));
            //Lấy chuỗi ký tự nhập từ bàn phím
            sentence_to_server = inFromUser.readLine();

            //Tạo socket cho client kết nối đến server qua ID address và port number
            Socket clientSocket = new Socket("127.0.0.1", 6543);

            //Tạo OutputStream nối với Socket
            DataOutputStream outToServer =
                    new DataOutputStream(clientSocket.getOutputStream());

            //Tạo inputStream nối với Socket
            BufferedReader inFromServer =
                    new BufferedReader(new
                            InputStreamReader(clientSocket.getInputStream()));

            String encryptedText = CypherUtils.encryptTextUsingAES(sentence_to_server, CypherUtils.secretAESKeyString);
            String encryptedAESKeyString = CypherUtils.encryptAESKey(CypherUtils.secretAESKeyString, privateKey);

            //Gửi chuỗi ký tự tới Server thông qua outputStream đã nối với Socket (ở trên)
//            outToServer.writeBytes(sentence_to_server + '\n');
            outToServer.writeBytes(encryptedAESKeyString + '\n');

            //Đọc tin từ Server thông qua InputSteam đã nối với socket
            sentence_from_server = inFromServer.readLine();

            String dencryptedAESKeyString = CypherUtils.decryptAESKey(sentence_from_server, Main.publicKey);
            String dencryptedText = CypherUtils.decryptTextUsingAES(dencryptedAESKeyString, CypherUtils.secretAESKeyString);

            //print kết qua ra màn hình
            System.out.println("FROM SERVER: " + dencryptedText);
            if (sentence_to_server.equals("end")) {
                //Đóng liên kết socket
                clientSocket.close();
                return;
            }
        }
    }

    // Get RSA keys. Uses key size of 2048.
    private static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String, Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }
}
