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

public class Main {
    public static void main2(String[] args) {
        final int servPort = 4321;
        final int RSAKeySize = 1024;
        final String newline = "\n";

        Key pubKey = null;
        ServerSocket cServer = null;
        Socket cClient = null;

        // Initialise RSA
        try {
            KeyPairGenerator RSAKeyGen = KeyPairGenerator.getInstance("RSA");
            RSAKeyGen.initialize(RSAKeySize);
            KeyPair pair = RSAKeyGen.generateKeyPair();
            pubKey = pair.getPublic();
        } catch (GeneralSecurityException e) {
            System.out.println(e.getLocalizedMessage() + newline);
            System.out.println("Error initialising encryption. Exiting.\n");
            System.exit(0);
        }

        // Initialise socket connection
        try {
            cServer = new ServerSocket(servPort);
            cClient = cServer.accept();
        } catch (IOException e) {
            System.out.println("Error initialising I/O.\n");
            System.exit(0);
        }

        // Send public key
        try {
            System.out.println(DatatypeConverter.printHexBinary(pubKey.getEncoded()));
            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(pubKey.getEncoded().length);
            cClient.getOutputStream().write(bb.array());
            cClient.getOutputStream().write(pubKey.getEncoded());
            cClient.getOutputStream().flush();
        } catch (IOException e) {
            System.out.println("I/O Error");
            System.exit(0);
        }
    }

    public static PrivateKey privateKey;
    public static PublicKey publicKey;

    public static void main(String argv[]) throws Exception {

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
        privateKey = (PrivateKey) keys.get("private");
        publicKey = (PublicKey) keys.get("public");

        String sentence_from_client;
        String sentence_to_client;

        //T???o socket server, ch??? t???i c???ng '6543'
        ServerSocket welcomeSocket = new ServerSocket(6543);


        boolean ready = true;
        while (ready) {
            //ch??? y??u c???u t??? client
            Socket connectionSocket = welcomeSocket.accept();

            //T???o input stream, n???i t???i Socket
            BufferedReader inFromClient =
                    new BufferedReader(new
                            InputStreamReader(connectionSocket.getInputStream()));

            //T???o outputStream, n???i t???i socket
            DataOutputStream outToClient =
                    new DataOutputStream(connectionSocket.getOutputStream());
            outToClient.writeBytes(DatatypeConverter.printHexBinary(publicKey.getEncoded()));
            //?????c th??ng tin t??? socket
            sentence_from_client = inFromClient.readLine();

            String dencryptedAESKeyString = CypherUtils.decryptAESKey(sentence_from_client, Main2.publicKey);
            String dencryptedText = CypherUtils.decryptTextUsingAES(dencryptedAESKeyString, CypherUtils.secretAESKeyString);
//            sentence_from_client = decryptAESKey(encryptedAESKeyString, publicKey);

            sentence_to_client = dencryptedText + " (Server accepted!)" + '\n';
            //ghi d??? li???u ra socket
            outToClient.writeBytes(sentence_to_client);

            if (sentence_from_client.equals("end")) {
                ready = false;
            }
        }

        return;
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
