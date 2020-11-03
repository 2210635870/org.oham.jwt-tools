import org.oham.jwttools.JwkValidationException;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.utils.ValidationUtil;
import org.oham.jwttools.vo.JwkVo;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @Author 欧航
 * @Description 测试 javax.validation 校验框架
 * @Date 2020/11/3 15:28
 * @Version 1.0
 **/
public class TestValidate {

    @Test
    public void testJwkVoValidation() {
        JwkVo jwkVo = JwkVo.builder().build();


        // 校验算法字段非空
        try {
            ValidationUtil.verifyJwkVo(jwkVo);
        } catch (JwkValidationException ex) {
            Assert.assertEquals(ex.getErrorCode(), "err.jwk.algorithm.isNotEmpty");
        }

        // 校验算法取值合法性
        jwkVo.setAlgorithm("UNKNOWN");
        try {
            ValidationUtil.verifyJwkVo(jwkVo);
        } catch (JwkValidationException ex) {
            Assert.assertEquals(ex.getErrorCode(), "err.jwk.algorithm.illegal");
        }

        // 校验私钥字段非空
        jwkVo.setAlgorithm(AlgorithmEnum.HS256.name());
        try {
            ValidationUtil.verifyJwkVo(jwkVo);
        } catch (JwkValidationException ex) {
            Assert.assertEquals(ex.getErrorCode(), "err.jwk.privateExponent.isNotEmpty");
        }

        // 校验公钥不需非空
        jwkVo.setAlgorithm(AlgorithmEnum.HS256.name());
        jwkVo.setPrivateExponent("test-secret-key");
        ValidationUtil.verifyJwkVo(jwkVo);

        // 校验公钥非空
        jwkVo.setAlgorithm(AlgorithmEnum.RSA512.name());
        try {
            ValidationUtil.verifyJwkVo(jwkVo);
        } catch (JwkValidationException ex) {
            Assert.assertEquals(ex.getErrorCode(), "err.jwk.publicExponent.isNotEmpty");
        }
    }
}
