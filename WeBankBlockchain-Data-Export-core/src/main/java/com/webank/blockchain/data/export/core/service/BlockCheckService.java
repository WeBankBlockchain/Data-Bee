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
import java.util.Optional;
import java.util.stream.Collectors;

import com.webank.blockchain.data.export.db.dao.BlockDetailInfoDAO;
import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;
import com.webank.blockchain.data.export.extractor.ods.EthClient;
import org.apache.commons.codec.binary.StringUtils;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import com.webank.blockchain.data.export.common.constants.BlockConstants;
import com.webank.blockchain.data.export.common.enums.BlockCertaintyEnum;
import com.webank.blockchain.data.export.common.enums.TxInfoStatusEnum;
import com.webank.blockchain.data.export.core.config.SystemEnvironmentConfig;

import cn.hutool.core.date.DateUtil;
import lombok.extern.slf4j.Slf4j;

/**
 * BlockTaskPoolService
 *
 * @Description: BlockTaskPoolService
 * @author maojiayu
 * @data Apr 1, 2019 5:08:19 PM
 *
 */
@Service
@Slf4j
public class BlockCheckService {

    @Autowired
    private BlockTaskPoolRepository blockTaskPoolRepository;
    @Autowired
    private BlockDetailInfoDAO blockDetailInfoDAO;
    @Autowired
    private RollBackService rollBackService;
    @Autowired
    private EthClient client;
    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;

    public void processErrors() {
        log.info("Begin to check error records");
        List<BlockTaskPool> unnormalRecords = blockTaskPoolRepository.findUnNormalRecords();
        if (CollectionUtils.isEmpty(unnormalRecords)) {
            return;
        } else {
            log.info("sync block detect {} error transactions.", unnormalRecords.size());
            unnormalRecords.parallelStream().map(b -> b.getBlockHeight()).forEach(e -> {
                log.error("Block {} sync error, and begin to rollback.", e);
                rollBackService.rollback(e, e + 1);
                blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.INIT.getStatus(),
                        new Date(), e);
            });
        }
    }

    public void checkForks(long currentBlockHeight) throws IOException {
        log.info("current block height is {}, and begin to check forks", currentBlockHeight);
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
                Block block = client.getBlock(BigInteger.valueOf(pool.getBlockHeight()));
                String newHash = block.getHash();
                if (!StringUtils.equals(newHash,
                        blockDetailInfoDAO.getBlockDetailInfoByBlockHeight(pool.getBlockHeight()).getBlockHash())) {
                    log.info("Block {} is forked!!! ready to resync", pool.getBlockHeight());
                    rollBackService.rollback(pool.getBlockHeight(), pool.getBlockHeight() + 1);
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

    public void checkTimeOut() {
        Date offsetDate = DateUtil.offsetSecond(DateUtil.date(), 0 - BlockConstants.DEPOT_TIME_OUT);
        log.info("Begin to check timeout transactions which is ealier than {}", offsetDate);
        List<BlockTaskPool> list = blockTaskPoolRepository
                .findBySyncStatusAndDepotUpdatetimeLessThan((short) TxInfoStatusEnum.DOING.getStatus(), offsetDate);
        if (!CollectionUtils.isEmpty(list)) {
            log.info("Detect {} timeout transactions.", list.size());
        }
        list.forEach(p -> {
            log.error("Block {} sync block timeout!!, the depot_time is {}, and the threshold time is {}",
                    p.getBlockHeight(), p.getDepotUpdatetime(), offsetDate);
            blockTaskPoolRepository.setSyncStatusByBlockHeight((short) TxInfoStatusEnum.TIMEOUT.getStatus(), new Date(),
                    p.getBlockHeight());
        });

    }

    public void checkTaskCount(long startBlockNumber, long currentMaxTaskPoolNumber) {
        log.info("Check task count from {} to {}", startBlockNumber, currentMaxTaskPoolNumber);
        if (isComplete(startBlockNumber, currentMaxTaskPoolNumber)) {
            return;
        }
        List<BlockTaskPool> supplements = new ArrayList<>();
        long t = startBlockNumber;
        for (long i = startBlockNumber; i <= currentMaxTaskPoolNumber
                - systemEnvironmentConfig.getCrawlBatchUnit(); i += systemEnvironmentConfig.getCrawlBatchUnit()) {
            long j = i + systemEnvironmentConfig.getCrawlBatchUnit() - 1;
            Optional<List<BlockTaskPool>> optional = findMissingPoolRecords(i, j);
            if (optional.isPresent()) {
                supplements.addAll(optional.get());
            }
            t = j + 1;
        }
        Optional<List<BlockTaskPool>> optional = findMissingPoolRecords(t, currentMaxTaskPoolNumber);
        if (optional.isPresent()) {
            supplements.addAll(optional.get());
        }
        log.info("Find {} missing pool numbers", supplements.size());
        blockTaskPoolRepository.saveAll(supplements);
    }

    public Optional<List<BlockTaskPool>> findMissingPoolRecords(long startIndex, long endIndex) {
        if (isComplete(startIndex, endIndex)) {
            return Optional.empty();
        }
        List<BlockTaskPool> list = blockTaskPoolRepository.findByBlockHeightRange(startIndex, endIndex);
        List<Long> ids = list.stream().map(p -> p.getBlockHeight()).collect(Collectors.toList());
        List<BlockTaskPool> supplements = new ArrayList<>();
        for (long tmpIndex = startIndex; tmpIndex <= endIndex; tmpIndex++) {
            if (ids.indexOf(tmpIndex) >= 0) {
                continue;
            }
            log.info("Successfully detect block {} is missing. Try to sync block again.", tmpIndex);
            BlockTaskPool pool = new BlockTaskPool().setBlockHeight(tmpIndex)
                    .setSyncStatus((short) TxInfoStatusEnum.ERROR.getStatus())
                    .setCertainty((short) BlockCertaintyEnum.UNCERTAIN.getCertainty());
            supplements.add(pool);
        }
        return Optional.of(supplements);
    }

    public boolean isComplete(long startBlockNumber, long currentMaxTaskPoolNumber) {
        long deserveCount = currentMaxTaskPoolNumber - startBlockNumber + 1;
        long actualCount = blockTaskPoolRepository.countByBlockHeightRange(startBlockNumber, currentMaxTaskPoolNumber);
        log.info("Check task count from block {} to {}, deserve count is {}, and actual count is {}", startBlockNumber,
                currentMaxTaskPoolNumber, deserveCount, actualCount);
        if (deserveCount == actualCount) {
            return true;
        } else {
            return false;
        }
    }

}
