import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.utils.ValidationUtil;
import org.oham.jwttools.vo.JwkVo;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Map;

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


        // 校验算法字段和私钥字段非空
        Map<String, String> errMap1 = ValidationUtil.validateVo(jwkVo);
        System.out.println(errMap1);
        Assert.assertFalse(errMap1.isEmpty());
        Assert.assertTrue(errMap1.containsKey("err.jwk.algorithm.isNotEmpty"));
        Assert.assertTrue(errMap1.containsKey("err.jwk.privateExponent.isNotEmpty"));

        // 校验算法取值合法性

        jwkVo.setAlgorithm("UNKNOWN");
        Map<String, String> errMap2 = ValidationUtil.validateVo(jwkVo);
        System.out.println(errMap2);
        Assert.assertFalse(errMap2.isEmpty());
        Assert.assertFalse(errMap2.containsKey("err.jwk.algorithm.isNotEmpty"));
        Assert.assertTrue(errMap2.containsKey("err.jwk.algorithm.illegal"));


        // 校验公钥不需非空

        jwkVo.setAlgorithm(AlgorithmEnum.HS256.name());
        jwkVo.setPrivateExponent("test-secret-key");
        Map<String, String> errMap3 = ValidationUtil.validateVo(jwkVo);
        System.out.println(errMap3);
        Assert.assertTrue(errMap3.isEmpty());

        // 校验公钥非空
        jwkVo.setAlgorithm(AlgorithmEnum.RSA512.name());
        jwkVo.setPrivateExponent("test-secret-key");
        Map<String, String> errMap4 = ValidationUtil.validateVo(jwkVo);
        System.out.println(errMap4);
        Assert.assertFalse(errMap4.isEmpty());
        Assert.assertTrue(errMap4.containsKey("err.jwk.publicExponent.isNotEmpty"));


    }
}
