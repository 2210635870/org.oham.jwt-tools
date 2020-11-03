package org.oham.jwttools.enumerations;

import org.oham.jwttools.utils.KeyUtil;
import org.oham.jwttools.vo.JwkVo;

/**
 * @Author 欧航
 * @Description 支持的 JWT 签名算法枚举
 * @Version 1.0
 **/
public enum AlgorithmEnum {

    /** HMAC with SHA-256 */
    HS256("HMAC256"),

    /** HMAC with SHA-384 */
    HS384("HMAC384"),

    /** HMAC with SHA-512 */
    HS512("HMAC512"),

    /** RSASSA-PKCS1-v1_5 with SHA-256 */
    RSA256("RSA256"),

    /** RSASSA-PKCS1-v1_5 with SHA-384 */
    RSA384("RSA384"),

    /** RSASSA-PKCS1-v1_5 with SHA-512 */
    RSA512("RSA512"),

    /** ECDSA with curve P-256 and SHA-256 */
    ES256("ECDSA256"),

    /** ECDSA with curve secp256k1 and SHA-256 */
    ES256K("ECDSA256K"),

    /** ECDSA with curve P-384 and SHA-384 */
    ES384("ECDSA384"),

    /** ECDSA with curve P-521 and SHA-512 */
    ES512("ECDSA512");

    private String name;

    AlgorithmEnum(String name) {
        this.name = name;
    }

    /**
     * @Author 欧航
     * @Description 获取算法名称
     * @Date 2020/10/29 17:54
     * @return java.lang.String
     **/
    public String getName() {
        return name;
    }

    /**
     * @Author 欧航
     * @Description 用于初始化 Jwk VO, 方便生成 AlgorithmBuilder 入参
     * @Date 2020/10/29 17:34
     * @return org.oham.jwttools.vo.JwkVo
     **/
   public JwkVo initJwkVO() {
       return JwkVo.builder()
               .algorithm(this.name())
               .kid(KeyUtil.genKeyId())
               .build();
   }
    /**
     * @Author 欧航
     * @Description 用于初始化 Jwk VO, 方便生成 AlgorithmBuilder 入参（不自动生成 KeyId）
     * @Date 2020/10/29 17:34
     * @return org.oham.jwttools.vo.JwkVo
     **/
    public JwkVo initJwkVoWithNoKeyId() {
        return JwkVo.builder()
                .algorithm(this.name())
                .build();
    }
}
