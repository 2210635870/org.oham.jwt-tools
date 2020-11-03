package org.oham.jwttools.vo;

import lombok.Builder;
import lombok.Data;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.validation.EnumValueLimit;
import org.oham.jwttools.validation.PublicExponentCheckNull;

import javax.validation.constraints.NotBlank;


/**
 * @Author 欧航
 * @Description Json Web Key 数据对象
 * @Date 2020/10/29 16:49
 * @Version 1.0
 **/
@Data
@Builder
@PublicExponentCheckNull(algorithmField = "algorithm", publicKeyField = "publicExponent",
        algorithmLimits = {AlgorithmEnum.ES256, AlgorithmEnum.ES256K,
                            AlgorithmEnum.ES384, AlgorithmEnum.ES512,
                            AlgorithmEnum.RSA256, AlgorithmEnum.RSA384,
                            AlgorithmEnum.RSA512},
        message = "###err.jwk.publicExponent.isNotEmpty###")
public class JwkVo {

    /** 签名算法 */
    @NotBlank(message = "###err.jwk.algorithm.isNotEmpty###")
    @EnumValueLimit(target = AlgorithmEnum.class, message = "###err.jwk.algorithm.illegal###")
    private String algorithm;

    /** 密钥 ID */
    private String kid;

    /** 私钥 / 对称密钥 */
    @NotBlank(message = "###err.jwk.privateExponent.isNotEmpty###")
    private String privateExponent;

    /** 公钥 */
    private String publicExponent;
}
