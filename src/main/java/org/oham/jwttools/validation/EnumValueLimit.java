package org.oham.jwttools.validation;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * @Author 欧航
 * @Description 校验请求参数属性必须为指定枚举中的值
 * @Date 2020/11/3 9:14
 * @Version 1.0
 */
@Target({FIELD})
@Retention(RUNTIME)
@Constraint(validatedBy = EnumValueValidator.class)
@Documented
public @interface EnumValueLimit {

    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    Class<?>[] target() default {};
}
