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
package com.webank.blockchain.data.export.task;

import cn.hutool.core.collection.CollectionUtil;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.constants.BlockConstants;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.enums.DataType;
import com.webank.blockchain.data.export.parser.contract.ContractParser;
import com.webank.blockchain.data.export.service.BlockAsyncService;
import com.webank.blockchain.data.export.service.BlockCheckService;
import com.webank.blockchain.data.export.service.BlockDepotService;
import com.webank.blockchain.data.export.service.BlockIndexService;
import com.webank.blockchain.data.export.service.BlockPrepareService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.fisco.bcos.sdk.transaction.codec.decode.TransactionDecoderService;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * GenerateCodeApplicationRunner
 *
 * @author maojiayu
 * @Description: GenerateCodeApplicationRunner
 * @date 2018年11月29日 下午4:37:38
 */

@Slf4j
@Data
public class CrawlRunner {

    private DataExportContext context;

    private long startBlockNumber;

    private AtomicBoolean runSwitch = new AtomicBoolean(false);

    public static CrawlRunner create(DataExportContext context){
        return new CrawlRunner(context);
    }

    private CrawlRunner(DataExportContext context) {
        this.context = context;
    }

    public void export() {
        checkConfig();
        if (!runSwitch.get()){
            log.info("data export config check failed, task already stop");
            return;
        }
        //abi、bin parse
        ContractMapsInfo mapsInfo = ContractParser.initContractMaps(ExportConstant.getCurrentContext().getConfig().getContractInfoList());
        ContractConstants.setCurrentContractMaps(mapsInfo);
        DataPersistenceManager.getCurrentManager().buildDataStore();
        handle();
    }

    private void checkConfig() {
        if (CollectionUtil.isEmpty(context.getExportDataSource().getMysqlDataSources())) {
            log.error("mysqlDataSources is not set，please set it ！！！");
            return;
        }
        if (context.getEsConfig() != null && context.getEsConfig().isEnable()) {
            if (context.getEsConfig().getClusterName() == null){
                log.error("clusterName is not set，please set it ！！！");
            }
            if (context.getEsConfig().getIp() == null){
                log.error("es ip is not set，please set it ！！！");
            }
            if (context.getEsConfig().getPort() <= 0){
                log.error("es port is not set，please set it ！！！");
            }
        }
        if (context.getExportDataSource().isSharding()) {
            if (context.getExportDataSource().getShardingNumberPerDatasource() == 0) {
                log.error("shardingNumberPerDatasource is zero, please set it to a number greater than 0 ");
                return;
            }
            if (context.getExportDataSource().getMysqlDataSources().size() < 2) {
                log.error("isSharding is true, mysqlDataSources size must >= 2 ");
                return;
            }
        }
        if (context.getChainInfo().getNodeStr() == null) {
            log.error("nodeStr is not set，please set it ！！！ ");
            return;
        }
        if (context.getChainInfo().getCertPath() == null) {
            log.error("certPath is not set，please set it ！！！ ");
            return;
        }
        if (CollectionUtil.isEmpty(context.getConfig().getDataTypeBlackList())) {
            context.getConfig().setDataTypeBlackList(DataType.getDefault());
        }
        if (context.getConfig().getCrawlBatchUnit() < 1) {
            log.error("The batch unit threshold can't be less than 1!!");
            return;
        }
        if (CollectionUtil.isNotEmpty(context.getConfig().getContractInfoList())) {
            for(ContractInfo contractInfo : context.getConfig().getContractInfoList()){
                if (contractInfo.getAbi() == null || contractInfo.getBinary() == null || contractInfo.getContractName() == null) {
                    log.error("contract information is not complete, please set it ！！！ ");
                    return;
                }
            }
        }
        runSwitch.getAndSet(true);
    }

    public long getHeight(long height) {
        return Math.max(height, startBlockNumber);
    }

    /**
     * The key driving entrance of single instance depot: 1. check timeout txs and process errors; 2. produce tasks; 3.
     * consume tasks; 4. check the fork status; 5. rollback; 6. continue and circle;
     *
     */
    public void handle() {
        try{
            ExportConstant.getCurrentContext().setDecoder(new TransactionDecoderService(
                    ExportConstant.getCurrentContext().getClient().getCryptoSuite()));
            DataPersistenceManager.getCurrentManager().saveContractInfo();
        }catch (Exception e) {
            log.error("save Contract Info, {}", e.getMessage());
        }

        try {
            startBlockNumber = BlockIndexService.getStartBlockIndex();
            log.info("Start succeed, and the block number is {}", startBlockNumber);
        } catch (Exception e) {
            log.error("depot Error, {}", e.getMessage());
        }
        while (!Thread.currentThread().isInterrupted() && runSwitch.get()) {
            try {
                long currentChainHeight = BlockPrepareService.getCurrentBlockHeight();
                long fromHeight = getHeight(BlockPrepareService.getTaskPoolHeight());
                // control the batch unit number
                long end = fromHeight + context.getConfig().getCrawlBatchUnit() - 1;
                long toHeight = Math.min(currentChainHeight, end);
                log.info("Current depot status: {} of {}, and try to process block from {} to {}", fromHeight - 1,
                        currentChainHeight, fromHeight, toHeight);
                boolean certainty = toHeight + 1 < currentChainHeight - BlockConstants.MAX_FORK_CERTAINTY_BLOCK_NUMBER;
                if (fromHeight <= toHeight) {
                    log.info("Try to sync block number {} to {} of {}", fromHeight, toHeight, currentChainHeight);
                    BlockPrepareService.prepareTask(fromHeight, toHeight, certainty);
                } else {
                    // single circle sleep time is read from the application.properties
                    log.info("No sync block tasks to prepare, begin to sleep {} s",
                            context.getConfig().getFrequency());
                    try {
                        Thread.sleep(context.getConfig().getFrequency() * 1000);
                    }catch (InterruptedException e){
                        Thread.currentThread().interrupt();
                    }
                }
                log.info("Begin to fetch at most {} tasks", context.getConfig().getCrawlBatchUnit());
                List<Block> taskList = BlockDepotService.fetchData(context.getConfig().getCrawlBatchUnit());
                for (Block b : taskList) {
                    BlockAsyncService.handleSingleBlock(b, currentChainHeight);
                }
                if (!certainty) {
                    BlockCheckService.checkForks(currentChainHeight);
                    BlockCheckService.checkTaskCount(startBlockNumber, currentChainHeight);
                }
                BlockCheckService.checkTimeOut();
                BlockCheckService.processErrors();
            } catch (Exception e) {
                log.error("CrawlRunner run failed ", e);
                try {
                    Thread.sleep(60 * 1000L);
                } catch (InterruptedException interruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        log.info("DataExportExecutor already ended ！！！");
    }



}