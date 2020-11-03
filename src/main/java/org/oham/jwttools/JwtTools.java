package org.oham.jwttools;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.oham.jwttools.utils.ValidationUtil;
import org.oham.jwttools.vo.JwkVo;

import java.nio.charset.Charset;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;


/**
 * @Author 欧航
 * @Description Jwt token 生成工具
 * @Date 2020/10/28 17:53
 * @Version 1.0
 **/
@Slf4j
public class JwtTools {


    /**
     * @Author 欧航
     * @Description 生成 Token
     * @Date 2020/10/30 14:40
     * @param jwk: JWK json web key vo 对象
     * @param jwtBuilder: JWT.create() builder
     * @return java.lang.String
     **/
    public static String createToken(JwkVo jwk, JWTCreator.Builder jwtBuilder) {
        ValidationUtil.verifyJwkVo(jwk);

        Algorithm alg = new AlgorithmBuilder().getAlgorithm(jwk);
        String token = jwtBuilder.sign(alg);

        log.debug("Generate token: {}", token);
        return token;
    }

    /**
     * @Author 欧航
     * @Description 校验 JWT token
     * @Date 2020/11/2 10:42
     * @param jwk: JWK 密钥 VO 对象
     * @param token: JWT token 字符串
     * @return com.auth0.jwt.interfaces.DecodedJWT JWT 校验通过后的解码对象
     */
    public static DecodedJWT verifySign(JwkVo jwk, String token) {
        log.debug("Begin to verify token: {}", token);
        ValidationUtil.verifyJwkVo(jwk);

        Algorithm alg = new AlgorithmBuilder().getAlgorithm(jwk);
        JWTVerifier verifier = JWT.require(alg).build();
        //Reusable verifier instance
        DecodedJWT jwt = verifier.verify(token);

        log.debug("Decoded token header: {} \npayload: {}\nsignature: {}\nkey id: {}\nexpireAt: {}\nalgorithm: {}",
                new String(Base64.decodeBase64(jwt.getHeader()), Charset.defaultCharset()),
                new String(Base64.decodeBase64(jwt.getPayload()), Charset.defaultCharset()),
                jwt.getSignature(),
                jwt.getKeyId(),
                LocalDateTime.ofInstant(jwt.getExpiresAt().toInstant(),
                        ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                jwt.getAlgorithm());

        return jwt;
    }
}
