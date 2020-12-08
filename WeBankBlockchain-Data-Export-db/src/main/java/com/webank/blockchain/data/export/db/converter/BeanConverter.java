/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.db.converter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.webank.blockchain.data.export.db.entity.IdEntity;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.bo.data.CommonBO;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.exceptions.UtilException;
import cn.hutool.core.util.ClassLoaderUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * BeanConvert
 *
 * @Description: BeanConvert
 * @author maojiayu
 * @data Jul 5, 2019 4:18:21 PM
 *
 */
@Service
@Slf4j
public class BeanConverter {
    public IdEntity convertBOToEntity(CommonBO bo, String type)
            throws InstantiationException, IllegalAccessException, UtilException {
        IdEntity entity = (IdEntity) ClassLoaderUtil
                .loadClass("com.webank.blockchain.data.export.db.generated.entity." + type + "." + bo.getIdentifier()).newInstance();
        BeanUtil.copyProperties(bo, entity);
        return entity;
    }

    public List<IdEntity> convertToEntities(Collection<CommonBO> bos, String type) {
        List<IdEntity> list = new ArrayList<>(bos.size());
        bos.forEach(bo -> {
            try {
                list.add(convertBOToEntity(bo, type));
            } catch (InstantiationException | IllegalAccessException | UtilException e) {
                log.error("Bean convert error", e);
            }
        });
        return list;
    }

}
