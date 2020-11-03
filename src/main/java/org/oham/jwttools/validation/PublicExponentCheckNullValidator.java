package org.oham.jwttools.validation;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.beanutils.BeanUtils;
import org.oham.jwttools.enumerations.AlgorithmEnum;
import org.oham.jwttools.utils.ConstantsUtil;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @Author 欧航
 * @Description 校验请求参数属性必须为指定枚举中的值
 * @Date 2020/11/3 10:26
 * @Version 1.0
 **/
@Slf4j
public class PublicExponentCheckNullValidator
        implements ConstraintValidator<PublicExponentCheckNull, Object> {

    /** 依赖的签名算法字段 */
    private String algorithmField;

    /** 公钥字段 */
    private String publicKeyField;

    /** 须校验公钥非空的算法项 */
    private AlgorithmEnum[] algorithmLimits;

    @Override
    public void initialize(PublicExponentCheckNull constraint) {
        this.algorithmField = constraint.algorithmField();
        this.publicKeyField = constraint.publicKeyField();
        this.algorithmLimits = constraint.algorithmLimits();
    }

    @Override
    public boolean isValid(Object object, ConstraintValidatorContext context) {
        if (this.algorithmLimits == null || this.algorithmLimits.length == 0) {
            return true;
        }
        try {
            String algorithm = BeanUtils.getProperty(object, algorithmField);
            boolean algLimitIsMatch = Arrays.stream(algorithmLimits).anyMatch(e -> e.name().equals(algorithm));

            if (algLimitIsMatch) {
                String publicKey = BeanUtils.getProperty(object, publicKeyField);
                return publicKey != null && publicKey.length() > 0;
            } else {
                return true;
            }
        } catch (Exception e) {
            log.error("PublicExponentCheckNullValidator validation process error: ", e);
        }
        return false;
    }

}
