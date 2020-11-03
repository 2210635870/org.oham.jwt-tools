package org.oham.jwttools.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.oham.jwttools.vo.EcdsaKeyPairVo;
import org.oham.jwttools.vo.RsaKeyPairVo;

import java.net.InetAddress;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @Author 欧航
 * @Description Json 工具类
 * @Date 2020/10/26 18:32
 * @Version 1.0
 **/
@Slf4j
public class KeyUtil {
    private static final int RSA_KEY_SIZE = 1024;
    private static final int ECDSA_KEY_SIZE = 256;
    private static final AtomicInteger SEQ = new AtomicInteger(10000);
    private static final DateTimeFormatter DF_FMT_PREFIX = DateTimeFormatter.ofPattern("yyMMddHHmmssSS");

    /**
     * @Author 欧航
     * @Description 生成 RSA 密钥对 VO 对象
     * @Date 2020/10/30 16:03
     * @return org.oham.jwttools.vo.RsaKeyPairVo
     */
    public static RsaKeyPairVo generateRsaKeyPair() throws Exception {
        RsaKeyPairVo vo = new RsaKeyPairVo();

        KeyPairGenerator gen = KeyPairGenerator.getInstance(ConstantsUtil.RSA_ALGORITHM);
        gen.initialize(RSA_KEY_SIZE, new SecureRandom());

        KeyPair keyPair = gen.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        String pubKey = Base64.encodeBase64String(rsaPublicKey.getEncoded());
        String priKey = Base64.encodeBase64String(rsaPrivateKey.getEncoded());
        String rsaModulus = Base64.encodeBase64String(rsaPrivateKey.getModulus().toByteArray());

        log.debug("Generated RSA key pair and packed to de jwk vo, \npublic key: {}\nprivate key: {}\nmodulus:{}",
                pubKey, priKey, rsaModulus);

        vo.setPublicKeyStr(pubKey);
        vo.setPrivateKeyStr(priKey);
        vo.setPublicKey(rsaPublicKey);
        vo.setPrivateKey(rsaPrivateKey);

        return vo;
    }


    /**
     * @Author 欧航
     * @Description 生成 ECDSA 密钥对 VO 对象
     * @Date 2020/10/30 16:03
     * @param curveName:  ECDSA 标准曲线名称
     * @return org.oham.jwttools.vo.RsaKeyPairVo
     */
    public static EcdsaKeyPairVo generateEcdsaKeyPair(String curveName) throws Exception {
        EcdsaKeyPairVo vo = new EcdsaKeyPairVo();

        KeyPairGenerator gen = KeyPairGenerator.getInstance(ConstantsUtil.ECDSA_ALGORITHM);
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curveName);

        try {
            gen.initialize(ecGenParameterSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException ex) {
            log.error("Curve name: {} is not supported currently by this jdk version: {}",
                    curveName, System.getProperty("java.version"));
            throw ex;
        }

        SecureRandom random = new SecureRandom();
        gen.initialize(ECDSA_KEY_SIZE, random);

        KeyPair keyPair = gen.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

        String pubKey = Base64.encodeBase64String(ecPublicKey.getEncoded());
        String priKey = Base64.encodeBase64String(ecPrivateKey.getEncoded());

        log.debug("Generated ECDSA key pair and packed to de jwk vo, \npublic key: {}\nprivate key: {}",
                pubKey, priKey);

        vo.setPublicKeyStr(pubKey);
        vo.setPrivateKeyStr(priKey);
        vo.setPublicKey(ecPublicKey);
        vo.setPrivateKey(ecPrivateKey);

        return vo;
    }

    /**
     * @Author 欧航
     * @Description 通过公钥 byte[] 将公钥还原，适用于 RSA 算法
     * @Date 2020/10/30 15:20
     * @param pubKeyEncoded:  encodeBase64String 公钥字符串
     * @return java.security.interfaces.RSAPublicKey
     */
    public static RSAPublicKey restoreRsaPublicKey(String pubKeyEncoded) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKeyEncoded));
        KeyFactory keyFactory = KeyFactory.getInstance(ConstantsUtil.RSA_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return (RSAPublicKey)publicKey;
    }

    /**
     * @Author 欧航
     * @Description 通过私钥 byte[] 将公钥还原，适用于 RSA 算法
     * @Date 2020/10/30 15:20
     * @param priKeyEncoded:  encodeBase64String 私钥字符串
     * @return java.security.PrivateKey
     */
    public static RSAPrivateKey restoreRsaPrivateKey(String priKeyEncoded) throws
            NoSuchAlgorithmException,InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyEncoded));
        KeyFactory keyFactory = KeyFactory.getInstance(ConstantsUtil.RSA_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return (RSAPrivateKey)privateKey;
    }


    /**
     * @Author 欧航
     * @Description 通过公钥 byte[] 将公钥还原，适用于 ECDSA 算法
     * @Date 2020/10/30 15:20
     * @param pubKeyEncoded:  encodeBase64String 公钥字符串
     * @return java.security.interfaces.RSAPublicKey
     */
    public static ECPublicKey restoreEcdsaPublicKey(String pubKeyEncoded) throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKeyEncoded));
        KeyFactory keyFactory = KeyFactory.getInstance(ConstantsUtil.ECDSA_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return (ECPublicKey)publicKey;
    }

    /**
     * @Author 欧航
     * @Description 通过私钥 byte[] 将公钥还原，适用于 ECDSA 算法
     * @Date 2020/10/30 15:20
     * @param priKeyEncoded:  encodeBase64String 私钥字符串
     * @return java.security.PrivateKey
     */
    public static ECPrivateKey restoreEcdsaPrivateKey(String priKeyEncoded) throws
            NoSuchAlgorithmException,InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyEncoded));
        KeyFactory keyFactory = KeyFactory.getInstance(ConstantsUtil.ECDSA_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return (ECPrivateKey)privateKey;
    }


    /**
     * @Author 欧航
     * @Description 生成唯一 Key ID
     * @Date 2020/10/30 17:54
     * @return java.lang.String
     */
    public static String genKeyId() {
        LocalDateTime dataTime = LocalDateTime.now(ZoneId.systemDefault());
        if (SEQ.intValue() > ConstantsUtil.KEY_ID_SEQ_BOUND) {
            SEQ.getAndSet(10000);
        }
        return ConstantsUtil.KEY_ID_PREFIX + dataTime.format(DF_FMT_PREFIX) + getLocalIpSuffix() + SEQ.getAndIncrement();
    }

    private volatile static String IP_SUFFIX = null;
    /**
     * @Author 欧航
     * @Description 获取本机 IP 后两段，用于拼凑 Key Id，使 Key Id 生成的唯一性适用与分布式环境
     * @Date 2020/10/30 17:48
     * @return java.lang.String
     **/
    private static String getLocalIpSuffix() {
        if (null != IP_SUFFIX) {
            return IP_SUFFIX;
        }

        try {
            synchronized (KeyUtil.class) {
                if (null != IP_SUFFIX) {
                    return IP_SUFFIX;
                }

                InetAddress addr = InetAddress.getLocalHost();
                String hostAddress = addr.getHostAddress();

                if (null != hostAddress && hostAddress.length() > ConstantsUtil.IP_LEAST_LEN) {
                    String[] ipPart = hostAddress.trim().split("\\.");
                    StringBuffer ipSuffixA = new StringBuffer(ipPart[2]);
                    StringBuffer ipSuffixB = new StringBuffer(ipPart[3]);

                    while (ipSuffixA.length() < ConstantsUtil.IP_PART_LEN) {
                        ipSuffixA.insert(0, "0");
                    }

                    while (ipSuffixB.length() < ConstantsUtil.IP_PART_LEN) {
                        ipSuffixB.insert(0, "0");
                    }

                    IP_SUFFIX = ipSuffixA.append(ipSuffixB).toString();
                    return IP_SUFFIX;
                }

                IP_SUFFIX = ThreadLocalRandom.current().nextInt(100000, 999999) + "";
                return IP_SUFFIX;
            }
        } catch (Exception e) {
            log.debug("Get local IP failed", e);
            IP_SUFFIX = ThreadLocalRandom.current().nextInt(100000, 999999) + "";
            return IP_SUFFIX;
        }
    }
}
