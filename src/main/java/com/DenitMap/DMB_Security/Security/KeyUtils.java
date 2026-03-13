package com.DenitMap.DMB_Security.Security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class KeyUtils {

    @Value("classpath:Keys/private.pem")
    private Resource privateKey;

    @Value("classpath:keys/public.pem")
    private Resource publicKey;


    public PrivateKey loadPrivateKey(){

        try{

            String pem = new String(privateKey.getInputStream().readAllBytes());
            pem = pem.replace("-----BEGIN PRIVATE KEY-----","")
                    .replace("-----END PRIVATE KEY-----","")
                    .replaceAll("\\s","");

            byte[] decoded = Base64.getDecoder().decode(pem);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        }catch (Exception e){

            throw new IllegalArgumentException("Failed to Load the Private Key",e);

        }
    }

    public PublicKey loadPublicKey(){
        try{
            String pem = new String(publicKey.getInputStream().readAllBytes());
            pem = pem.replace("-----BEGIN PUBLIC KEY-----","")
                    .replace("-----END PUBLIC KEY-----","")
                    .replaceAll("\\s","");

            byte[] decoded = Base64.getDecoder().decode(pem);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load pubic key",e);
        }
    }
}