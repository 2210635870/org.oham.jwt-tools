import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import org.oham.jwttools.JwtTools;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.utils.ConstantsUtil;
import org.oham.jwttools.utils.KeyUtil;
import org.oham.jwttools.vo.EcdsaKeyPairVo;
import org.oham.jwttools.vo.JwkVo;
import org.oham.jwttools.vo.RsaKeyPairVo;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Calendar;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

/**
 * @Author 欧航
 * @Description 测试 token 生成与校验的性能
 * @Date 2020/11/2 16:36
 * @Version 1.0
 **/
public class TestPerformance {

    static {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        loggerContext.getLogger("org.oham.jwttools").setLevel(Level.INFO);
    }

    /**
     * @Author 欧航
     * @Description 测试生成 8000 个 token 用时
     * @Date 2020/11/2 17:01
     * @return void
     */
    @Test
    public void testGenerateHS256Token() {

        long st = System.currentTimeMillis();
        IntStream.range(0,8000).parallel().forEach(i->{
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

            JwtTools.createToken(jwkVo, jwtBuilder);
        });
        long ed = System.currentTimeMillis();

        System.out.println("HMAC256 generate 8000 token took " + (ed-st)/1000 + " sec");
    }

    /**
     * @Author 欧航
     * @Description 验证 token 性能测试
     * @Date 2020/11/2 17:15
     * @return void
     */
    @Test
    public void testVerifyHS256Token() {
        Map<String, JwkVo> tokenMap = new ConcurrentHashMap<>(8192);
        IntStream.range(0,8000).parallel().forEach(i->{
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

            String token =  JwtTools.createToken(jwkVo, jwtBuilder);
            tokenMap.put(token, jwkVo);
        });

        System.out.println("Generate token finished");

        long st = System.currentTimeMillis();
        AtomicInteger cnt = new AtomicInteger(0);
        tokenMap.entrySet().stream().parallel().forEach(entry -> {
            cnt.incrementAndGet();
            JwtTools.verifySign(entry.getValue(), entry.getKey());
        });
        long ed = System.currentTimeMillis();

        System.out.println("HMAC256 verify " + cnt.get() + " token took " + (ed-st)/1000 + " sec");
    }


    /**
     * @Author 欧航
     * @Description 测试生成 800 个 RSA token 用时
     * @Date 2020/11/2 17:01
     * @return void
     */
    @Test
    public void testGenerateRSA256Token() {

        long st = System.currentTimeMillis();
        IntStream.range(0,800).parallel().forEach(i->{
            try {
                JwkVo jwkVo = AlgorithmEnum.RSA256.initJwkVO();
                // 生成并设置 RSA 密钥对
                RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
                jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
                jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

                JWTCreator.Builder jwtBuilder = JWT.create()
                        .withIssuer("org.oham")
                        .withKeyId(jwkVo.getKid())
                        .withIssuedAt(Calendar.getInstance().getTime())
                        .withExpiresAt(Date.from(
                                LocalDateTime.now().plusMinutes(60)
                                .atZone(ZoneId.systemDefault())
                                .toInstant()));

                JwtTools.createToken(jwkVo, jwtBuilder);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        long ed = System.currentTimeMillis();

        System.out.println("RSA256 generate 800 token took " + (ed-st)/1000 + " sec");
    }

    /**
     * @Author 欧航
     * @Description 验证 800 个 RSA token 性能测试
     * @Date 2020/11/2 17:15
     * @return void
     */
    @Test
    public void testVerifyRSA256Token() {
        Map<String, JwkVo> tokenMap = new ConcurrentHashMap<>(1024);
        IntStream.range(0,800).parallel().forEach(i->{
            try {
                JwkVo jwkVo = AlgorithmEnum.RSA256.initJwkVO();
                // 生成并设置 RSA 密钥对
                RsaKeyPairVo rsaKeyPairVo = KeyUtil.generateRsaKeyPair();
                jwkVo.setPrivateExponent(rsaKeyPairVo.getPrivateKeyStr());
                jwkVo.setPublicExponent(rsaKeyPairVo.getPublicKeyStr());

                JWTCreator.Builder jwtBuilder = JWT.create()
                        .withIssuer("org.oham")
                        .withKeyId(jwkVo.getKid())
                        .withIssuedAt(Calendar.getInstance().getTime())
                        .withExpiresAt(Date.from(
                                LocalDateTime.now().plusMinutes(60)
                                        .atZone(ZoneId.systemDefault())
                                        .toInstant()));

                String token = JwtTools.createToken(jwkVo, jwtBuilder);
                tokenMap.put(token, jwkVo);
            } catch (Exception e) {
                e.printStackTrace();
            }

        });

        System.out.println("Generate token finished");

        long st = System.currentTimeMillis();
        AtomicInteger cnt = new AtomicInteger(0);
        tokenMap.entrySet().stream().parallel().forEach(entry -> {
            cnt.incrementAndGet();
            JwtTools.verifySign(entry.getValue(), entry.getKey());
        });
        long ed = System.currentTimeMillis();

        System.out.println("RSA256 verify " + cnt.get() + " token took " + (ed-st) + " ms");
    }

    /**
     * @Author 欧航
     * @Description 测试生成 8000 个 ES256K token 用时
     * @Date 2020/11/2 17:01
     * @return void
     */
    @Test
    public void testGenerateES256KToken() {

        long st = System.currentTimeMillis();
        IntStream.range(0,8000).parallel().forEach(i->{
            try {
                JwkVo jwkVo = AlgorithmEnum.ES256K.initJwkVO();
                // 生成并设置 ECDSA 密钥对
                EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_SEC_P_256K1);
                jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
                jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

                JWTCreator.Builder jwtBuilder = JWT.create()
                        .withIssuer("org.oham")
                        .withKeyId(jwkVo.getKid())
                        .withIssuedAt(Calendar.getInstance().getTime())
                        .withExpiresAt(Date.from(
                                LocalDateTime.now().plusMinutes(60)
                                        .atZone(ZoneId.systemDefault())
                                        .toInstant()));

                JwtTools.createToken(jwkVo, jwtBuilder);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        long ed = System.currentTimeMillis();

        System.out.println("ES256K generate 800 token took " + (ed-st)/1000 + " sec");
    }

    /**
     * @Author 欧航
     * @Description 验证 8000 个 ES256K token 性能测试
     * @Date 2020/11/2 17:15
     * @return void
     */
    @Test
    public void testVerifyES256KToken() {
        Map<String, JwkVo> tokenMap = new ConcurrentHashMap<>(1024);
        IntStream.range(0,8000).parallel().forEach(i->{
            try {
                JwkVo jwkVo = AlgorithmEnum.ES256K.initJwkVO();
                // 生成并设置 ECDSA 密钥对
                EcdsaKeyPairVo ecdsaKeyPairVo = KeyUtil.generateEcdsaKeyPair(ConstantsUtil.ECDSA_SEC_P_256K1);
                jwkVo.setPrivateExponent(ecdsaKeyPairVo.getPrivateKeyStr());
                jwkVo.setPublicExponent(ecdsaKeyPairVo.getPublicKeyStr());

                JWTCreator.Builder jwtBuilder = JWT.create()
                        .withIssuer("org.oham")
                        .withKeyId(jwkVo.getKid())
                        .withIssuedAt(Calendar.getInstance().getTime())
                        .withExpiresAt(Date.from(
                                LocalDateTime.now().plusMinutes(60)
                                        .atZone(ZoneId.systemDefault())
                                        .toInstant()));

                String token = JwtTools.createToken(jwkVo, jwtBuilder);
                tokenMap.put(token, jwkVo);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        System.out.println("Generate token finished");

        long st = System.currentTimeMillis();
        AtomicInteger cnt = new AtomicInteger(0);
        tokenMap.entrySet().stream().parallel().forEach(entry -> {
            cnt.incrementAndGet();
            JwtTools.verifySign(entry.getValue(), entry.getKey());
        });
        long ed = System.currentTimeMillis();

        System.out.println("ES256K verify " + cnt.get() + " token took " + (ed-st) + " ms");
    }

}
