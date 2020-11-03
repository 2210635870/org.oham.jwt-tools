package org.oham.jwttools.utils;

import lombok.extern.slf4j.Slf4j;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.groups.Default;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @Author 欧航
 * @Description Javax.validation 公共校验工具类
 * @Date 2020/11/3 15:11
 * @Version 1.0
 **/
@Slf4j
public class ValidationUtil {
    /**
     * javax.validation-api 校验器
     */
    private static ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();

    /**
     * @Author 欧航
     * @Description 校验入参 VO 对象属性值
     * @Date 2020/11/3 15:14
     * @param vo: vo 数据对象
     * @param groups: 校验分组
     * @return java.util.Map<java.lang.String,java.lang.String>
     */
    public static <T> Map<String, String> validateVo(T vo, Class<?>... groups) {
        Validator validator = validatorFactory.getValidator();

        if (groups == null || groups.length == 0) {
            groups = new Class[]{Default.class};
        }

        Set<ConstraintViolation<T>> validateResult = validator.validate(vo, groups);

        //如果校验通过，返回空集合
        if (validateResult.isEmpty()) {
            return Collections.emptyMap();
        } else {
            LinkedHashMap<String, String> errors = new LinkedHashMap<>(4);
            Pattern pattern = Pattern.compile(ConstantsUtil.ERR_MAG_PATTERN);

            for (ConstraintViolation<T> violation : validateResult) {
                Matcher matcher = pattern.matcher(violation.getMessage());
                if (matcher.find()) {
                    String code = matcher.group(1);
                    errors.put(matcher.group(1), PropsUtil.getProperty(code));
                }
            }
            return errors;
        }
    }

    /**
     * @Author 欧航
     * @Description 校验入参 VO 对象属性值（抛异常）
     * @Date 2020/11/3 15:23
     * @param vo: vo 数据对象
     * @param groups: 校验分组
     */
    /*public static <T> void validateVoException(T vo, Class<?>... groups) {
        Map<String, String> errors = validateVo(dto, groups);
        if (!errors.isEmpty()) {
            Map.Entry<String, String> entry = errors.entrySet().iterator().next();
            log.warn(entry.getKey().concat(" - ").concat(entry.getValue()));
            throw new BusinessException(entry.getKey(), entry.getValue());
        }
    }*/
}
