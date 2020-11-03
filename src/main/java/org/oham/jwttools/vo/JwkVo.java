package org.oham.jwttools.vo;

import lombok.Builder;
import lombok.Data;

/**
 * @Author 欧航
 * @Description Json Web Key 数据对象
 * @Date 2020/10/29 16:49
 * @Version 1.0
 **/
@Data
@Builder
public class JwkVo {

    /** 签名算法 */
    private String algorithm;

    /** 密钥 ID */
    private String kid;

    /** 私钥 / 对称密钥 */
    private String privateExponent;

    /** 公钥 */
    private String publicExponent;
}
