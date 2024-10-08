package com.function;

import java.util.*;
import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * Azure Functions with HTTP Trigger.
 */
public class ChecksumHttpTrigger 
{
    
    private static PublicKey pubKey;

    @FunctionName("ChecksumHttpTrigger")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {HttpMethod.GET, HttpMethod.POST}, authLevel = AuthorizationLevel.FUNCTION) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        


        // Parse query parameter
        String queryChecksum = request.getQueryParameters().get("checksum");
        String checksum = request.getBody().orElse(queryChecksum);

        if (checksum == null) 
        {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass checksum value on the query string or in the request body").build();
        }
        
        /*
        String queryPubkey = request.getQueryParameters().get("pubkey");
        String pubkey = request.getBody().orElse(queryPubkey);
        if (pubkey == null) 
        {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Please pass pubkey value on the query string or in the request body").build();
        }
        */
       
        String pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsSc3/q/AFJg4YvGDxdCDFfU1CJpdjAYm5IB5nFDBgtFsYot5iSp8s6UXk7YEWyaID9P16jphP/a9q0SUQL/S/MX+ifrGB5ZFkpq0wFDPnudU4rDG70WapNFywI0f9Vf1kXwko3yjtKUl/D20aW+Hx4nwpa7IHGMEcFfStV7aemi1i580rcEfNlUahpK7xRW8+jztF6F4F+yqt9u+RneNT6ldfUM46W2+hRxlGNN8qMKcHvJ/JpqBh+KoPhxh1LG72rEH/jkJGnPGf4uQhpZkU1xMx/5rbFrvh2sUa0uI789LgatS27NSbBciW5Hj/jXYsb/OI14LC5+B9828QZVyVwIDAQAB";

        String signature = getChecksum(pubkey, checksum);
        return request.createResponseBuilder(HttpStatus.OK).body(signature).build();
    }


    public static String getChecksum(String PublicKey, String StrToEnc) {
        
        String ArrivedHash = "";
        try 
        {
            ArrivedHash = encryptDataRSA(StrToEnc, PublicKey);
        } 
        catch (Exception e) 
        {
            ArrivedHash = "NA";
        }
        return ArrivedHash;
    }

    private static String encryptDataRSA(String message, String PubKey)
        throws InvalidAlgorithmParameterException, InvalidAlgorithmParameterException 
        {
           
            String encodedEncryptedBytes = "";
            String hashString = PubKey;
            try 
            {
                byte[] encryptedBytes = encryptRSA(message.getBytes(), PubKey);
                byte[] base64Bytes = Base64.encodeBase64(encryptedBytes, false);
                encodedEncryptedBytes = new String(base64Bytes);
                hashString = DigestUtils.sha256Hex(encodedEncryptedBytes);
            } 
            catch (Exception ex) 
            {
                System.out.println("Exception " + ex.getMessage());
            }
            return hashString;
             
        }

        private static byte[] encryptRSA(byte[] data, String pub) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
        {
            byte[] publicBytes = Base64.decodeBase64(pub.getBytes());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            try 
            {
                pubKey = keyFactory.generatePublic(keySpec);
            } 
            catch (Exception e) 
            {
                System.out.println("Exception " + e.getMessage());
            }
            Cipher ciph = Cipher.getInstance("RSA/ECB/NoPadding");
            ciph.init(Cipher.ENCRYPT_MODE, pubKey);
            return ciph.doFinal(data);
        }
}
