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

import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * BlockAsyncService
 *
 * @Description: BlockAsyncService
 * @author maojiayu
 * @data Jun 27, 2019 3:54:56 PM
 *
 */
@ConditionalOnProperty(name = "system.multiLiving", havingValue = "false")
@Service
public class BlockAsyncService {
    @Autowired
    private BlockDepotService blockDepotService;

    @Async("taskExecutor")
    public void handleSingleBlock(Block b, long total) {
        blockDepotService.process(b, total);
    }
}
