package org.oham.jwttools;

import com.auth0.jwt.algorithms.Algorithm;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.vo.JwkVo;


/**
 * @Author 欧航
 * @Description 算法对象生成器
 * @Date 2020/10/29 17:15
 * @Version 1.0
 **/
class AlgorithmBuilder {

    Algorithm getAlgorithm(JwkVo vo) {
        AlgorithmEnum algorithmEnum = AlgorithmEnum.valueOf(vo.getAlgorithm());

        Algorithm algorithm = null;
        switch (algorithmEnum) {
            case HS256: {
                algorithm = Algorithm.HMAC256(vo.getPrivateExponent());
                break;
            }
            case HS384: {
                algorithm = Algorithm.HMAC384(vo.getPrivateExponent());
                break;
            }
            case HS512: {
                algorithm = Algorithm.HMAC512(vo.getPrivateExponent());
                break;
            }
            case RSA256: {
                algorithm = Algorithm.RSA256(ProvidedRsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case RSA384: {
                algorithm = Algorithm.RSA384(ProvidedRsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case RSA512: {
                algorithm = Algorithm.RSA512(ProvidedRsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case ES256: {
                algorithm = Algorithm.ECDSA256(ProvidedEcdsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case ES256K: {
                algorithm = Algorithm.ECDSA256K(ProvidedEcdsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case ES384: {
                algorithm = Algorithm.ECDSA384(ProvidedEcdsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            case ES512: {
                algorithm = Algorithm.ECDSA512(ProvidedEcdsaKeyPairProvider
                        .builder()
                        .srcPublicKey(vo.getPublicExponent())
                        .srcPrivateKey(vo.getPrivateExponent())
                        .build());
                break;
            }
            default: {
                throw new IllegalArgumentException("Not support algorithm yet :" + algorithmEnum.getName());
            }
        }

        return algorithm;
    }
}