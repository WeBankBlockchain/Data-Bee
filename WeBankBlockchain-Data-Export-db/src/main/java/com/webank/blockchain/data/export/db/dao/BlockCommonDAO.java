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
package com.webank.blockchain.data.export.db.dao;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.webank.blockchain.data.export.db.converter.BeanConverter;
import com.webank.blockchain.data.export.db.entity.IdEntity;
import com.webank.blockchain.data.export.db.service.RepositoryService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.common.bo.data.CommonBO;

import lombok.extern.slf4j.Slf4j;

/**
 * BlockEventDAO
 *
 * @Description: BlockEventDAO
 * @author maojiayu
 * @data Jul 8, 2019 2:15:27 PM
 *
 */
@Component
@Slf4j
public class BlockCommonDAO {
    @Autowired
    private BeanConverter beanConverter;
    @Autowired
    private RepositoryService repositoryService;

    public void save(List<CommonBO> bos, String type) {
        Map<String, List<CommonBO>> map = bos.stream().collect(Collectors.toMap(k -> k.getIdentifier(),
                v -> Lists.newArrayList(v), (List<CommonBO> newValueList, List<CommonBO> oldValueList) -> {
                    oldValueList.addAll(newValueList);
                    return oldValueList;
                }));
        String postfix = type.equalsIgnoreCase("event") ? "EventRepository" : "MethodRepository";
        List<IdEntity> entities = beanConverter.convertToEntities(bos, type);
        map.forEach((k, v) -> {
            if (!repositoryService.getRepository(StringUtils.uncapitalize(k) + postfix).isPresent()) {
                log.error("{} not existed", StringUtils.uncapitalize(k) + postfix);
                return;
            }
            BaseDAO.saveAllWithTimeLog(repositoryService.getRepository(StringUtils.uncapitalize(k) + postfix).get(),
                    entities);
        });

    }
}
