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

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.date.DateUtil;
import com.webank.blockchain.data.export.common.constants.BlockConstants;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.enums.BlockCertaintyEnum;
import com.webank.blockchain.data.export.common.enums.TxInfoStatusEnum;
import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;
import com.webank.blockchain.data.export.task.DataPersistenceManager;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * BlockTaskPoolService
 *
 * @Description: BlockTaskPoolService
 * @author maojiayu
 * @data Apr 1, 2019 5:08:19 PM
 *
 */
@Slf4j
@Data
public class BlockCheckService {

    public static void processErrors() {
        log.info("Begin to check error records");
        BlockTaskPoolRepository blockTaskPoolRepository =
                DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository();
        List<BlockTaskPool> unnormalRecords = blockTaskPoolRepository.findUnNormalRecords();
        if (!CollectionUtil.isEmpty(unnormalRecords)) {
            log.info("sync block detect {} error transactions.", unnormalRecords.size());
            for(BlockTaskPool taskPool : unnormalRecords) {
                log.error("Block {} sync error, and begin to rollback.", taskPool.getBlockHeight());
                RollBackService.rollback(taskPool.getBlockHeight(), taskPool.getBlockHeight() + 1);
                blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.INIT.getStatus(),
                        new Date(), taskPool.getBlockHeight());
            }
        }
    }

    public static void checkForks(long currentBlockHeight) throws IOException {
        log.info("current block height is {}, and begin to check forks", currentBlockHeight);
        BlockTaskPoolRepository blockTaskPoolRepository =
                DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository();
        List<BlockTaskPool> uncertainBlocks =
                blockTaskPoolRepository.findByCertainty((short) BlockCertaintyEnum.UNCERTAIN.getCertainty());
        for (BlockTaskPool pool : uncertainBlocks) {
            if (pool.getBlockHeight() <= currentBlockHeight - BlockConstants.MAX_FORK_CERTAINTY_BLOCK_NUMBER) {
                if (pool.getSyncStatus() == TxInfoStatusEnum.DOING.getStatus()) {
                    log.error("block {} is doing!", pool.getBlockHeight());
                    continue;
                }
                if (pool.getSyncStatus() == TxInfoStatusEnum.INIT.getStatus()) {
                    log.error("block {} is not sync!", pool.getBlockHeight());
                    blockTaskPoolRepository.setCertaintyByBlockHeight((short) BlockCertaintyEnum.FIXED.getCertainty(),
                            pool.getBlockHeight());
                    continue;
                }
                Block block = BlockCrawlService.getBlock(BigInteger.valueOf(pool.getBlockHeight()));
                String newHash = block.getHash();
                if (!newHash.equals(
                        DataPersistenceManager.getCurrentManager().getBlockDetailInfoRepository()
                                .findByBlockHeight(pool.getBlockHeight()).getBlockHash())) {
                    log.info("Block {} is forked!!! ready to resync", pool.getBlockHeight());
                    RollBackService.rollback(pool.getBlockHeight(), pool.getBlockHeight() + 1);
                    blockTaskPoolRepository.setSyncStatusAndCertaintyByBlockHeight(
                            (short) TxInfoStatusEnum.INIT.getStatus(), (short) BlockCertaintyEnum.FIXED.getCertainty(),
                            pool.getBlockHeight());
                } else {
                    log.info("Block {} is not forked!", pool.getBlockHeight());
                    blockTaskPoolRepository.setCertaintyByBlockHeight((short) BlockCertaintyEnum.FIXED.getCertainty(),
                            pool.getBlockHeight());
                }

            }
        }

    }

    public static void checkTimeOut() {
        BlockTaskPoolRepository blockTaskPoolRepository =
                DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository();
        Date offsetDate = DateUtil.offsetSecond(DateUtil.date(), -BlockConstants.DEPOT_TIME_OUT);
        log.info("Begin to check timeout transactions which is ealier than {}", offsetDate);
        List<BlockTaskPool> list = blockTaskPoolRepository
                .findBySyncStatusAndDepotUpdatetimeLessThan((short) TxInfoStatusEnum.DOING.getStatus(), offsetDate);
        if (!CollectionUtil.isEmpty(list)) {
            log.info("Detect {} timeout transactions.", list.size());
        }
        list.forEach(p -> {
            log.error("Block {} sync block timeout!!, the depot_time is {}, and the threshold time is {}",
                    p.getBlockHeight(), p.getDepotUpdatetime(), offsetDate);
            blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.TIMEOUT.getStatus(), new Date(),
                    p.getBlockHeight());
        });

    }

    public static void checkTaskCount(long startBlockNumber, long currentMaxTaskPoolNumber) {
        log.info("Check task count from {} to {}", startBlockNumber, currentMaxTaskPoolNumber);
        BlockTaskPoolRepository blockTaskPoolRepository =
                DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository();
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        if (isComplete(startBlockNumber, currentMaxTaskPoolNumber)) {
            return;
        }
        List<BlockTaskPool> supplements = new ArrayList<>();
        long t = startBlockNumber;
        for (long i = startBlockNumber; i <= currentMaxTaskPoolNumber
                - config.getCrawlBatchUnit(); i += config.getCrawlBatchUnit()) {
            long j = i + config.getCrawlBatchUnit() - 1;
            Optional<List<BlockTaskPool>> optional = findMissingPoolRecords(i, j);
            optional.ifPresent(supplements::addAll);
            t = j + 1;
        }
        Optional<List<BlockTaskPool>> optional = findMissingPoolRecords(t, currentMaxTaskPoolNumber);
        optional.ifPresent(supplements::addAll);
        log.info("Find {} missing pool numbers", supplements.size());
        blockTaskPoolRepository.saveAll(supplements);
    }

    public static Optional<List<BlockTaskPool>> findMissingPoolRecords(long startIndex, long endIndex) {
        BlockTaskPoolRepository blockTaskPoolRepository =
                DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository();
        if (isComplete(startIndex, endIndex)) {
            return Optional.empty();
        }
        List<BlockTaskPool> list = blockTaskPoolRepository.findByBlockHeightRange(startIndex, endIndex);
        List<Long> ids = list.stream().map(BlockTaskPool::getBlockHeight).collect(Collectors.toList());
        List<BlockTaskPool> supplements = new ArrayList<>();
        for (long tmpIndex = startIndex; tmpIndex <= endIndex; tmpIndex++) {
            if (ids.contains(tmpIndex)) {
                continue;
            }
            log.info("Successfully detect block {} is missing. Try to sync block again.", tmpIndex);
            BlockTaskPool pool = new BlockTaskPool().setBlockHeight(tmpIndex)
                    .setSyncStatus((short) TxInfoStatusEnum.ERROR.getStatus())
                    .setCertainty((short) BlockCertaintyEnum.UNCERTAIN.getCertainty())
                    .setDepotUpdatetime(new Date());
            supplements.add(pool);
        }
        return Optional.of(supplements);
    }

    public static boolean isComplete(long startBlockNumber, long currentMaxTaskPoolNumber) {
        long deserveCount = currentMaxTaskPoolNumber - startBlockNumber + 1;
        long actualCount = DataPersistenceManager.getCurrentManager().getBlockTaskPoolRepository()
                .countByBlockHeightRange(startBlockNumber, currentMaxTaskPoolNumber);
        log.info("Check task count from block {} to {}, deserve count is {}, and actual count is {}", startBlockNumber,
                currentMaxTaskPoolNumber, deserveCount, actualCount);
        return deserveCount == actualCount;
    }

}
