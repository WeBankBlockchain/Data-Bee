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

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;
import com.webank.blockchain.data.export.extractor.ods.EthClient;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.enums.TxInfoStatusEnum;

import lombok.extern.slf4j.Slf4j;

/**
 * BlockSyncService
 *
 * @Description: BlockSyncService
 * @author maojiayu
 * @data Apr 1, 2019 5:02:39 PM
 *
 */
@Service
@Slf4j
public class BlockDepotService {
    @Autowired
    private BlockCrawlService BlockCrawlService;
    @Autowired
    private BlockTaskPoolRepository blockTaskPoolRepository;
    @Autowired
    private BlockStoreService blockStoreService;

    @Autowired
    private EthClient ethClient;

    public List<Block> fetchData(int count) {
        List<BlockTaskPool> tasks = blockTaskPoolRepository
                .findBySyncStatusOrderByBlockHeightLimit((short) TxInfoStatusEnum.INIT.getStatus(), count);
        return getTasks(tasks);
    }

    public List<Block> getTasks(List<BlockTaskPool> tasks) {
        List<Block> result = new ArrayList<>();
        List<BlockTaskPool> pools = new ArrayList<>();
        for (BlockTaskPool task : tasks) {
            task.setSyncStatus((short) TxInfoStatusEnum.DOING.getStatus()).setDepotUpdatetime(new Date());
            BigInteger bigBlockHeight = new BigInteger(Long.toString(task.getBlockHeight()));
            Block block;
            try {
                block = ethClient.getBlock(bigBlockHeight);
                result.add(block);
                pools.add(task);
            } catch (IOException e) {
                log.error("Block {},  exception occur in job processing: {}", task.getBlockHeight(), e.getMessage());
                blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.ERROR.getStatus(),
                        new Date(), task.getBlockHeight());
            }
        }
        blockTaskPoolRepository.saveAll(pools);
        log.info("Successful fetch {} Blocks.", result.size());
        return result;
    }

    public void processDataSequence(List<Block> data, long total) {
        for (Block b : data) {
            process(b, total);
        }
    }

    public void process(Block b, long total) {
        try {
            BlockInfoBO blockInfo = BlockCrawlService.parse(b);
            blockStoreService.store(blockInfo);
            blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.DONE.getStatus(), new Date(),
                    b.getNumber().longValue());
            log.info("Block {} of {} sync block succeed.", b.getNumber().longValue(), total);
        } catch (IOException e) {
            log.error("block {}, exception occur in job processing: {}", b.getNumber().longValue(), e.getMessage());
            blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.ERROR.getStatus(), new Date(),
                    b.getNumber().longValue());
        }
    }

}
