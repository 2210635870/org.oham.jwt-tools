package org.oham.jwttools.vo;

import lombok.Data;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @Author 欧航
 * @Description ECDSA 密钥对 vo 对象
 * @Date 2020/11/2 15:14
 * @Version 1.0
 **/
@Data
public class EcdsaKeyPairVo {

    /** encodeBase64String ECDSA 公钥字符串 */
    private String publicKeyStr;

    /** encodeBase64String ECDSA 私钥字符串 */
    private String privateKeyStr;

    /** ECDSA 公钥 */
    private ECPublicKey publicKey;

    /** ECDSA 私钥 */
    private ECPrivateKey privateKey;
}
