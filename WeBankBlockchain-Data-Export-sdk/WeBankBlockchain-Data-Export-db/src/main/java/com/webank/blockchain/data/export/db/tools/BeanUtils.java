package com.webank.blockchain.data.export.db.tools;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.ReflectUtil;
import cn.hutool.db.Entity;


/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/17
 */
public class BeanUtils {

    public static <T> T toBean(Entity entity, Class<T> clazz) {
        return BeanUtil.fillBeanWithMap(entity, ReflectUtil.newInstance(clazz), true, true);
    }
}
