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
package com.webank.blockchain.data.export.service;

import com.webank.blockchain.data.export.task.DataPersistenceManager;
import lombok.extern.slf4j.Slf4j;

/**
 * RollBackService, rollback
 *
 * @Description: RollBackService
 * @author maojiayu
 * @data 2018-12-27 15:59:41
 *
 */
@Slf4j
public class RollBackService {

    /**
     * Do rollback, including events, methods, accounts, and details.
     * 
     * @param
     */
    public static void rollback(long start, long end) {
        DataPersistenceManager.getCurrentManager().getRollbackOneInterfaceList()
                .forEach(v -> {
            v.rollback(start, end);
        });
    }

}
