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

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;

import javax.annotation.PostConstruct;

import com.webank.blockchain.data.export.core.service.BlockCheckService;
import com.webank.blockchain.data.export.core.service.BlockIndexService;
import com.webank.blockchain.data.export.core.service.BlockPrepareService;
import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;
import org.fisco.bcos.sdk.client.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.dangdang.ddframe.job.api.ShardingContext;
import com.dangdang.ddframe.job.api.simple.SimpleJob;
import com.webank.blockchain.data.export.common.constants.BlockConstants;

import lombok.extern.slf4j.Slf4j;

/**
 * PrepareTaskJob
 *
 * @Description: PrepareTaskJob
 * @author maojiayu
 * @data Jan 11, 2019 10:03:29 AM
 * 
 */
@Service
@Slf4j
@Profile("!test")
@ConditionalOnProperty(name = "system.multiLiving", havingValue = "true")
public class PrepareTaskJob implements SimpleJob {
    @Autowired
    private Client client;
    @Autowired
    private BlockCheckService blockCheckService;
    @Autowired
    private BlockIndexService blockIndexService;
    @Autowired
    private BlockPrepareService blockPrepareService;
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    private long startBlockNumber;

    @PostConstruct
    public void setStartBlockNumber() throws ParseException, IOException, InterruptedException {
        startBlockNumber = blockIndexService.getStartBlockIndex();
        log.info("Start succeed, and the block number is {}", startBlockNumber);
    }

    /**
     * prepare to do tasks, and restored in block_task_pool. 1. check timeout txs and process errors; 2. prepare tasks;
     * 3. process forks;
     * 
     * @param ShardingContext: elastic-job
     * @return void
     * @see com.dangdang.ddframe.job.api.simple.SimpleJob#execute(com.dangdang.ddframe.job.api.ShardingContext)
     */
    @Override
    public void execute(ShardingContext shardingContext) {
        try {
            BigInteger blockNumber = client.getBlockNumber().getBlockNumber();
            long total = blockNumber.longValue();
            log.info("Current chain block number is:{}", total);
            long height = blockPrepareService.getTaskPoolHeight();
            height = height > startBlockNumber ? height : startBlockNumber;
            long end = height + systemEnvironmentConfig.getCrawlBatchUnit();
            long batchNo = total < end ? total : end;
            boolean certainty = end < total - BlockConstants.MAX_FORK_CERTAINTY_BLOCK_NUMBER;
            blockPrepareService.prepareTask(height, batchNo, certainty);
            if (!certainty) {
                blockCheckService.checkForks(total);
            }
            blockCheckService.checkTimeOut();
            blockCheckService.processErrors();

        } catch (IOException e) {
            log.error("Job {}, exception occur in job processing: {}", shardingContext.getTaskId(), e.getMessage());

        }

    }

}
