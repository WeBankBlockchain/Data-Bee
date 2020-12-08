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
package com.webank.blockchain.data.export.core.service;

import java.util.Map;

import com.webank.blockchain.data.export.db.repository.RollbackInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.enums.TxInfoStatusEnum;
import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;

import lombok.extern.slf4j.Slf4j;

/**
 * RollBackService, rollback
 *
 * @Description: RollBackService
 * @author maojiayu
 * @data 2018-12-27 15:59:41
 *
 */
@Service
@Slf4j
public class RollBackService {

    /** @Fields rollbackOneInterfaceMap : all repositories need to be rollback would implents RollbackInterface */
    @Autowired
    private Map<String, RollbackInterface> rollbackOneInterfaceMap;
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;

    /**
     * Do rollback, including events, methods, accounts, and details.
     * 
     * @param blockHeight
     */
    public void rollback(long blockHeight) {

        rollbackOneInterfaceMap.forEach((k, v) -> {
            v.rollback(blockHeight);
        });
    }

    /**
     * Do rollback, including events, methods, accounts, and details.
     * 
     * @param blockHeight
     */
    public void rollback(long start, long end) {

        rollbackOneInterfaceMap.forEach((k, v) -> {
            v.rollback(start, end);
        });
    }

    /**
     * process roll back according to block info and total block number. decide from which block to rollback.
     * 
     * @param block height, block status
     * @return begin block height
     */
    public long processRollback(long height, int status) {
        if (height >= systemEnvironmentConfig.getCrawlBatchUnit() && status != TxInfoStatusEnum.DONE.getStatus()) {
            log.info("Begin to rollback block from {}.", height - systemEnvironmentConfig.getCrawlBatchUnit());
            rollback(height - systemEnvironmentConfig.getCrawlBatchUnit());
            height = height - systemEnvironmentConfig.getCrawlBatchUnit();
        } else {
            log.info("Begin to rollback block from {} to {}.", height,
                    height + systemEnvironmentConfig.getCrawlBatchUnit());
            rollback(height);
        }
        return height;
    }

}
