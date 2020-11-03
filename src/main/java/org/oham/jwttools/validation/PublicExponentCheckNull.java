package org.oham.jwttools.validation;

import org.oham.jwttools.enumerations.AlgorithmEnum;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * @Author 欧航
 * @Description 共钥非空校验
 * @Date 2020/11/3 9:20
 * @Version 1.0
 */
@Target(ElementType.TYPE)
@Documented
@Retention(RUNTIME)
@Constraint(validatedBy = {PublicExponentCheckNullValidator.class})
public @interface PublicExponentCheckNull {
    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    Class<?>[] target() default {};

    /**
     * 依赖的签名算法字段
     *
     * @return
     */
    String algorithmField();

    /**
     * 公钥字段
     *
     * @return
     */
    String publicKeyField();

    /**
     * 须校验公钥非空的算法项
     *
     * @return
     */
    AlgorithmEnum[] algorithmLimits();

}
