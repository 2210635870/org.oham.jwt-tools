import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.oham.jwttools.utils.ConstantsUtil;
import org.oham.jwttools.utils.KeyUtil;
import org.oham.jwttools.vo.EcdsaKeyPairVo;
import org.oham.jwttools.vo.JwkVo;
import org.oham.jwttools.JwtTools;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.vo.RsaKeyPairVo;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @Author 欧航
 * @Description 测试demo
 * @Date 2020/10/26 16:10
 * @Version 1.0
 **/
public class TestCase {

    /**
     * @Author 欧航
     * @Description 测试生成 RSA 密钥对
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testGenRsaKeyPairs() throws Exception {
        RsaKeyPairVo rsaVo = KeyUtil.generateRsaKeyPair();

        RSAPublicKey pub = KeyUtil.restoreRsaPublicKey(rsaVo.getPublicKeyStr());
        RSAPrivateKey pri = KeyUtil.restoreRsaPrivateKey(rsaVo.getPrivateKeyStr());

        Assert.assertEquals(rsaVo.getPrivateKeyStr(), Base64.encodeBase64String(pri.getEncoded()));
        Assert.assertEquals(rsaVo.getPublicKeyStr(), Base64.encodeBase64String(pub.getEncoded()));
    }

    /**
     * @Author 欧航
     * @Description 测试生成 RSA 密钥对
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testGenEcdsaKeyPairs() throws Exception {
        EcdsaKeyPairVo ecdsaVoP256 = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_256);
        ECPublicKey pubP256 = KeyUtil.restoreEcdsaPublicKey(ecdsaVoP256.getPublicKeyStr());
        ECPrivateKey priP256 = KeyUtil.restoreEcdsaPrivateKey(ecdsaVoP256.getPrivateKeyStr());
        Assert.assertEquals(ecdsaVoP256.getPrivateKeyStr(), Base64.encodeBase64String(priP256.getEncoded()));
        Assert.assertEquals(ecdsaVoP256.getPublicKeyStr(), Base64.encodeBase64String(pubP256.getEncoded()));

        EcdsaKeyPairVo ecdsaVoP384 = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_384);
        ECPublicKey pubP384 = KeyUtil.restoreEcdsaPublicKey(ecdsaVoP384.getPublicKeyStr());
        ECPrivateKey priP384 = KeyUtil.restoreEcdsaPrivateKey(ecdsaVoP384.getPrivateKeyStr());
        Assert.assertEquals(ecdsaVoP384.getPrivateKeyStr(), Base64.encodeBase64String(priP384.getEncoded()));
        Assert.assertEquals(ecdsaVoP384.getPublicKeyStr(), Base64.encodeBase64String(pubP384.getEncoded()));

        // Curve name: secp512r1 is not supported currently by this jdk version: 1.8.0_251
        /*EcdsaKeyPairVo ecdsaVoP512 = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_512);
        ECPublicKey pubP512 = KeyUtil.restoreEcdsaPublicKey(ecdsaVoP512.getPublicKeyStr());
        ECPrivateKey priP512 = KeyUtil.restoreEcdsaPrivateKey(ecdsaVoP512.getPrivateKeyStr());
        Assert.assertEquals(ecdsaVoP512.getPrivateKeyStr(), Base64.encodeBase64String(priP512.getEncoded()));
        Assert.assertEquals(ecdsaVoP512.getPublicKeyStr(), Base64.encodeBase64String(pubP512.getEncoded()));*/

        EcdsaKeyPairVo ecdsaVoSecp256k1 = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_SEC_P_256K1);
        ECPublicKey pubSecp256k1 = KeyUtil.restoreEcdsaPublicKey(ecdsaVoSecp256k1.getPublicKeyStr());
        ECPrivateKey priSecp256k1 = KeyUtil.restoreEcdsaPrivateKey(ecdsaVoSecp256k1.getPrivateKeyStr());
        Assert.assertEquals(ecdsaVoSecp256k1.getPrivateKeyStr(), Base64.encodeBase64String(priSecp256k1.getEncoded()));
        Assert.assertEquals(ecdsaVoSecp256k1.getPublicKeyStr(), Base64.encodeBase64String(pubSecp256k1.getEncoded()));

    }

    /**
     * @Description 测试创建和校验 token
     * @Date 2020/11/2 10:54
     * @param jwkVo: JWK 密钥 VO 对象
     * @param jwtBuilder: JWT json 对象构造器
     * @return com.auth0.jwt.interfaces.DecodedJWT JWT 校验通过后的解码对象
     */
    private DecodedJWT createAndVerifyToken(JwkVo jwkVo, JWTCreator.Builder jwtBuilder) {
        // 创建 token
        String token = JwtTools.createToken(jwkVo, jwtBuilder);
        // 验证 token
        return JwtTools.verifySign(jwkVo, token);
    }

    /**
     * @Description 测试 HMAC256 算法签名
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testHS256() {
        JwkVo jwkVo = AlgorithmEnum.HS256.initJwkVO();
        jwkVo.setPrivateExponent("test");

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                            LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    /**
     * @Description 测试 HMAC512 算法签名
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testHS512() {
        JwkVo jwkVo = AlgorithmEnum.HS512.initJwkVO();
        jwkVo.setPrivateExponent("test-key");

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    /**
     * @Description 测试 RSA256 算法签名
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testRSA256() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.RSA256.initJwkVO();
        // 生成并设置 RSA 密钥对
        RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
        jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")                // 设置 token 发行者
                .withKeyId(jwkVo.getKid())                      // 设置 token key id
                .withIssuedAt(Calendar.getInstance().getTime()) // 设置 token 发行日期
                .withExpiresAt(Date.from(                       // 设置 token 失效日期 （60分钟有效时长）
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        // 测试生成并校验 token
        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    /**
     * @Description 测试 RSA256 算法签名
     * @Date 2020/11/2 10:51
     * @return void
     */
    @Test
    public void testRSA384() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.RSA384.initJwkVO();
        // 生成并设置 RSA 密钥对
        RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
        jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }


    @Test
    public void testES256() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.ES256.initJwkVO();
        // 生成并设置 RSA 密钥对
        EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_256);
        jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    @Test
    public void testES256K() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.ES256K.initJwkVO();
        // 生成并设置 RSA 密钥对
        EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_SEC_P_256K1);
        jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    @Test
    public void testES384() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.ES384.initJwkVO();
        // 生成并设置 RSA 密钥对
        EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_P_384);
        jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        createAndVerifyToken(jwkVo, jwtBuilder);
    }

    /**
     * @Author 欧航
     * @Description 测试校验 token 过期
     * @Date 2020/11/2 10:58
     * @return void
     */
    @Test
    public void testVerifyExpireToken() {
        JwkVo jwkVo = AlgorithmEnum.HS512.initJwkVO();
        jwkVo.setPrivateExponent("test-key");

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().minusMinutes(30)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        // 校验 Token 有效期，期待能捕获 TokenExpiredException
        Assert.assertThrows(TokenExpiredException.class, () -> createAndVerifyToken(jwkVo, jwtBuilder));
    }

    /**
     * @Author 欧航
     * @Description 测试校验 token 过期 (RSA 算法)
     * @Date 2020/11/2 10:58
     * @return void
     */
    @Test
    public void testVerifyExpireRSAToken() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.RSA512.initJwkVO();
        // 生成并设置 RSA 密钥对
        RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
        jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().minusMinutes(30)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        // 校验 Token 有效期，期待能捕获 TokenExpiredException
        Assert.assertThrows(TokenExpiredException.class, () -> createAndVerifyToken(jwkVo, jwtBuilder));
    }


    /**
     * @Author 欧航
     * @Description 测试校验 token 过期 (RSA 算法)
     * @Date 2020/11/2 10:58
     * @return void
     */
    @Test
    public void testVerifyExpireECDSAToken() throws Exception {
        JwkVo jwkVo = AlgorithmEnum.ES256K.initJwkVO();
        // 生成并设置 ECDSA 密钥对
        EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_SEC_P_256K1);
        jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
        jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withIssuer("org.oham.jwttools")
                .withKeyId(jwkVo.getKid())
                .withIssuedAt(Calendar.getInstance().getTime())
                .withExpiresAt(Date.from(
                        LocalDateTime.now().minusMinutes(30)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

        // 校验 Token 有效期，期待能捕获 TokenExpiredException
        Assert.assertThrows(TokenExpiredException.class, () -> createAndVerifyToken(jwkVo, jwtBuilder));
    }


    /**
     * @Author 欧航
     * @Description 测试 key id 生成并发性
     * @Date 2020/11/2 16:52
     * @return void
     */
    @Test
    public void testKeyIdUnique() {
        List<String> keyIds = Collections.synchronizedList(new ArrayList<>());
        // 并发生成 80000 个 KeyId
        IntStream.range(0,80000).parallel().forEach(i->{
            keyIds.add(KeyUtil.genKeyId());
        });

        List<String> filterKeyIds = keyIds.stream().distinct().collect(Collectors.toList());

        System.out.println("生成 KeyId 数：" + keyIds.size());
        System.out.println("过滤重复后 KeyId 数：" + filterKeyIds.size());
        System.out.println("重复 KeyId 数："+(keyIds.size()-filterKeyIds.size()));
    }
}
