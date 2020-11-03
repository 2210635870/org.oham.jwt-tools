package org.oham.jwttools.validation;

import lombok.extern.slf4j.Slf4j;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * @Author 欧航
 * @Description 校验请求参数属性必须为指定枚举中的值
 * @Date 2020/11/3 9:57
 * @Version 1.0
 **/
@Slf4j
public class EnumValueValidator implements ConstraintValidator<EnumValueLimit, String> {

    private Class<?>[] classes;

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.length() == 0) {
            return true;
        }

        for (Class<?> cls : classes) {
            if (!cls.isEnum()) {
                continue;
            }

            Object[] enumConstants = cls.getEnumConstants();
            try {
                Method method = cls.getMethod("name");
                for (Object constant : enumConstants) {
                    Object code = method.invoke(constant, null);
                    if (code.toString().toLowerCase().equalsIgnoreCase(value)) {
                        return true;
                    }
                }
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                log.error("EnumValueValidator validation process error: ", e);
            }
        }

        return false;

    }

    @Override
    public void initialize(EnumValueLimit constraint) {
        this.classes = constraint.target();
    }
}
