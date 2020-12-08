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
package com.webank.blockchain.data.export.core.task;

import java.util.List;

import com.webank.blockchain.data.export.core.service.BlockCheckService;
import com.webank.blockchain.data.export.core.service.BlockDepotService;
import com.webank.blockchain.data.export.core.service.BlockIndexService;
import com.webank.blockchain.data.export.core.service.BlockPrepareService;
import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.core.service.BlockAsyncService;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import com.webank.blockchain.data.export.common.constants.BlockConstants;

import lombok.extern.slf4j.Slf4j;

/**
 * GenerateCodeApplicationRunner
 *
 * @Description: GenerateCodeApplicationRunner
 * @author maojiayu
 * @date 2018年11月29日 下午4:37:38
 * 
 */

@Component
@Order(value = 1)
@Profile("!test")
@ConditionalOnProperty(name = "system.multiLiving", havingValue = "false")
@Slf4j
public class CrawlApplicationRunner implements ApplicationRunner {
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    @Autowired
    private BlockCheckService blockTaskPoolService;
    @Autowired
    private BlockAsyncService blockAsyncService;
    @Autowired
    private BlockDepotService blockSyncService;
    @Autowired
    private BlockIndexService blockIndexService;
    @Autowired
    private BlockPrepareService blockPrepareService;

    private long startBlockNumber;
    private boolean signal = true;

    public long getHeight(long height) {
        return height > startBlockNumber ? height : startBlockNumber;
    }

    /**
     * The key driving entrance of single instance depot: 1. check timeout txs and process errors; 2. produce tasks; 3.
     * consume tasks; 4. check the fork status; 5. rollback; 6. continue and circle;
     * 
     * @throws InterruptedException
     * 
     */
    public void handle() throws InterruptedException {
        try {
            startBlockNumber = blockIndexService.getStartBlockIndex();
            log.info("Start succeed, and the block number is {}", startBlockNumber);
        } catch (Exception e) {
            log.error("depot Error, {}", e.getMessage());
        }
        while (signal) {
            try {
                long currentChainHeight = blockPrepareService.getCurrentBlockHeight();
                long fromHeight = getHeight(blockPrepareService.getTaskPoolHeight());
                // control the batch unit number
                long end = fromHeight + systemEnvironmentConfig.getCrawlBatchUnit() - 1;
                long toHeight = currentChainHeight < end ? currentChainHeight : end;
                log.info("Current depot status: {} of {}, and try to process block from {} to {}", fromHeight - 1,
                        currentChainHeight, fromHeight, toHeight);
                boolean certainty = toHeight + 1 < currentChainHeight - BlockConstants.MAX_FORK_CERTAINTY_BLOCK_NUMBER;
                if (fromHeight <= toHeight) {
                    log.info("Try to sync block number {} to {} of {}", fromHeight, toHeight, currentChainHeight);
                    blockPrepareService.prepareTask(fromHeight, toHeight, certainty);
                } else {
                    // single circle sleep time is read from the application.properties
                    log.info("No sync block tasks to prepare, begin to sleep {} s",
                            systemEnvironmentConfig.getFrequency());
                    Thread.sleep(systemEnvironmentConfig.getFrequency() * 1000);
                }
                log.info("Begin to fetch at most {} tasks", systemEnvironmentConfig.getCrawlBatchUnit());
                List<Block> taskList = blockSyncService.fetchData(systemEnvironmentConfig.getCrawlBatchUnit());
                for (Block b : taskList) {
                    blockAsyncService.handleSingleBlock(b, currentChainHeight);
                }
                if (!certainty) {
                    blockTaskPoolService.checkForks(currentChainHeight);
                    blockTaskPoolService.checkTaskCount(startBlockNumber, currentChainHeight);
                }
                blockTaskPoolService.checkTimeOut();
                blockTaskPoolService.processErrors();
            } catch (Exception e) {
                log.error("{}", e);
                Thread.sleep(60 * 1000L);
            }
        }

    }

    @Override
    public void run(ApplicationArguments var1) throws InterruptedException {
        if (systemEnvironmentConfig.getCrawlBatchUnit() < 1) {
            log.error("The batch unit threshold can't be less than 1!!");
            System.exit(1);
        }
        handle();
    }
}