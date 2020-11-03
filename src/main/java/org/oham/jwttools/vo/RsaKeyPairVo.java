package org.oham.jwttools.vo;

import lombok.Data;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @Author 欧航
 * @Description RSA 密钥对 vo 对象
 * @Date 2020/10/30 15:55
 * @Version 1.0
 **/
@Data
public class RsaKeyPairVo {

    /** encodeBase64String RSA 公钥字符串 */
    private String publicKeyStr;

    /** encodeBase64String RSA 私钥字符串 */
    private String privateKeyStr;

    /** RSA 公钥 */
    private RSAPublicKey publicKey;

    /** RSA 私钥 */
    private RSAPrivateKey privateKey;
}
