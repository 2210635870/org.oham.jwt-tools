package org.oham.jwttools.utils;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

/**
 * @Author 欧航
 * @Description 项目配置加载
 * @Date 2020/11/3 15:05
 * @Version 1.0
 **/
@Slf4j
public class PropsUtil {

    /**
     * 业务异常配置文件
     */
    private static final String MESSAGE_FILE = "err_valid_msg.properties";
    private static Properties messageProps;

    static {
        messageProps = getPropertiesFromClassPath(MESSAGE_FILE);
    }

    /**
     * @Author 欧航
     * @Description 加载类路径下的配置文件
     * @Date 2020/11/3 15:06
     * @param fileName: 配置文件名（相对路径）
     * @return java.util.Properties
     */
    public static Properties getPropertiesFromClassPath(String fileName) {
        InputStream resourceAsStream = null;
        try {
            resourceAsStream = PropsUtil.class.getClassLoader().getResourceAsStream(fileName);
            Properties properties = new Properties();
            properties.load(resourceAsStream);
            return properties;
        } catch (IOException e) {
            log.error("Could not load Properties file : {} ,{}'", fileName, e);
            return null;
        } finally {
            if (Objects.nonNull(resourceAsStream)) {
                try {
                    resourceAsStream.close();
                } catch (IOException e) {
                    log.error("getPropertiesFromClassPath close stream error", e);
                }
            }
        }
    }

    /**
     * @Author 欧航
     * @Description 重新加载配置文件
     * @Date 2020/11/3 15:09
     * @return void
     */
    public static void reload() {
        messageProps = getPropertiesFromClassPath(MESSAGE_FILE);
    }

    /**
     * @Author 欧航
     * @Description 获取配置值
     * @Date 2020/11/3 15:10
     * @param propName:
     * @return java.lang.String
     */
    public static String getProperty(String propName) {
        if (Objects.isNull(messageProps)) {
            log.error(MESSAGE_FILE + " did not initialize yet");
            return null;
        }
        return messageProps.getProperty(propName);
    }
}
