package com.juejin;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * 使用nimbus-jose-jwt构建JWE令牌。
 */
public class WithPresetCEKJWE {
    public static void main(String[] args) throws NoSuchAlgorithmException, JOSEException, ParseException {
        // The JWE alg and enc
        JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP;
        EncryptionMethod enc = EncryptionMethod.A256GCM;

        // Generate an RSA key pair
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

        // Generate the Content Encryption Key (CEK)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(enc.cekBitLength());
        SecretKey cek = keyGenerator.generateKey();

        // Encrypt the JWE with the RSA public key + specified AES CEK
        JWEObject jwe = new JWEObject(
                new JWEHeader(alg, enc),
                new Payload("The true sign of intelligence is not knowledge but imagination."));
        jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
        String jweString = jwe.serialize();

        // Decrypt the JWE with the RSA private key
        jwe = JWEObject.parse(jweString);
        jwe.decrypt(new RSADecrypter(rsaPrivateKey));
        System.out.println("The true sign of intelligence is not knowledge but imagination.".equals(jwe.getPayload().toString()));

        // Decrypt JWE with CEK directly, with the DirectDecrypter in promiscuous mode
        jwe = JWEObject.parse(jweString);
        jwe.decrypt(new DirectDecrypter(cek, true));
        System.out.println("The true sign of intelligence is not knowledge but imagination.".equals(jwe.getPayload().toString()));


    }
}
