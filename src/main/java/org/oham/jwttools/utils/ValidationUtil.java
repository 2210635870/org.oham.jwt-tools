package org.oham.jwttools.utils;

import lombok.extern.slf4j.Slf4j;
import org.oham.jwttools.JwkValidationException;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.vo.JwkVo;

import java.util.Arrays;

/**
 * @Author 欧航
 * @Description Javax.validation 公共校验工具类
 * @Date 2020/11/3 15:11
 * @Version 1.0
 **/
@Slf4j
public class ValidationUtil {

    /** 需要校验公钥非空的签名算法集合 */
    private static final AlgorithmEnum[] PUBLIC_KEY_NEEDED_ALG = new AlgorithmEnum[] {
            AlgorithmEnum.ES256,AlgorithmEnum.ES256K,AlgorithmEnum.ES384,AlgorithmEnum.ES512,
            AlgorithmEnum.RSA256,AlgorithmEnum.RSA384,AlgorithmEnum.RSA512
    };

    /**
     * @Author 欧航
     * @Description 校验签名算法字段取值合法性
     * @Date 2020/11/3 16:37
     * @param jwkVo: JWK 密钥 vo 对象
     */
    public static void verifyJwkVo(JwkVo jwkVo) {
        String alg = jwkVo.getAlgorithm();
        String priKey = jwkVo.getPrivateExponent();

        if (alg == null || alg.length() == 0) {
            throw new JwkValidationException("err.jwk.algorithm.isNotEmpty",
                    PropsUtil.getProperty("err.jwk.algorithm.isNotEmpty"));
        }

        if (Arrays.stream(AlgorithmEnum.values()).noneMatch(e -> e.name().equals(alg))) {
            throw new JwkValidationException("err.jwk.algorithm.illegal",
                    PropsUtil.getProperty("err.jwk.algorithm.illegal"));
        }

        if (priKey == null || priKey.length() == 0) {
            throw new JwkValidationException("err.jwk.privateExponent.isNotEmpty",
                    PropsUtil.getProperty("err.jwk.privateExponent.isNotEmpty"));
        }

        String pubKey = jwkVo.getPublicExponent();
        if (Arrays.stream(PUBLIC_KEY_NEEDED_ALG).anyMatch(e -> e.name().equals(alg))) {
            if (pubKey == null || pubKey.length() == 0) {
                throw new JwkValidationException("err.jwk.publicExponent.isNotEmpty",
                        PropsUtil.getProperty("err.jwk.publicExponent.isNotEmpty"));
            }
        }
    }

}
