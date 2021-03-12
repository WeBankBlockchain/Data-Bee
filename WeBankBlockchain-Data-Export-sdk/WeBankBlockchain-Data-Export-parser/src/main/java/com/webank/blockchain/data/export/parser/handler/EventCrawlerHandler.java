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
package com.webank.blockchain.data.export.parser.handler;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.core.collection.ListUtil;
import cn.hutool.json.JSONUtil;
import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.EventMetaInfo;
import com.webank.blockchain.data.export.common.bo.contract.FieldVO;
import com.webank.blockchain.data.export.common.bo.data.EventBO;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.entity.TableSQL;
import com.webank.blockchain.data.export.common.tools.DateUtils;
import com.webank.blockchain.data.export.parser.service.TransactionService;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.abi.ABICodecException;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.TransactionObject;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.TransactionResult;
import org.fisco.bcos.sdk.client.protocol.response.BcosTransactionReceipt;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.utils.Numeric;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * EventCrawlerHandler
 *
 * @Description: EventCrawlerHandler
 * @author maojiayu
 * @data Jul 3, 2019 10:00:38 AM
 *
 */
@Slf4j
public class EventCrawlerHandler {


    @SuppressWarnings({ "rawtypes", "unused" })
    public static List<EventBO> crawl(Block block, Map<String, String> txHashContractNameMapping) throws IOException {
        List<TransactionResult> transactionResults = block.getTransactions();
        for (TransactionResult result : transactionResults) {
            TransactionObject to = (TransactionObject) result;
            JsonTransactionResponse transaction = to.get();
            BcosTransactionReceipt bcosTransactionReceipt = ExportConstant.getCurrentContext().getClient()
                    .getTransactionReceipt(transaction.getHash());
            Optional<TransactionReceipt> opt = bcosTransactionReceipt.getTransactionReceipt();
            if (opt.isPresent()) {
                TransactionReceipt tr = opt.get();
                if (transaction.getTo() != null && !transaction.getTo().equals(ContractConstants.EMPTY_ADDRESS)) {
                    tr.setContractAddress(transaction.getTo());
                }
                Optional<String> contractName = TransactionService.getContractNameByTransaction(
                        transaction, txHashContractNameMapping);
                if (!contractName.isPresent()) {
                    continue;
                }
                Map<String, ContractInfo> contractAbiMap = ExportConstant.getCurrentContext().getContractInfoMap();
                String abi = contractAbiMap.get(contractName.get()).getAbi();
                if (abi == null) {
                    continue;
                }
                return parserEvent(contractAbiMap, contractName.get(), abi, tr,block);
            }
        }
        return ListUtil.empty();
    }

    private static List<EventBO> parserEvent(Map<String, ContractInfo> contractAbiMap, String contractName, String abi,
                                             TransactionReceipt tr,Block block){
        List<EventBO> boList = new ArrayList<>();
        ContractDetail contractDetail = ContractConstants.getCurrentContractMaps().getContractBinaryMap()
                .get(contractAbiMap.get(contractName).getBinary());
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        List<EventMetaInfo> eventMetaInfos = contractDetail.getEventMetaInfos();

        Map<String,EventMetaInfo> eventMetaInfoMap = eventMetaInfos.stream()
                .collect(Collectors.toMap(EventMetaInfo::getEventName, e->e));
        Map<String, List<List<Object>>> events = null;
        try {
            events = ExportConstant.getCurrentContext().getDecoder()
                    .decodeEvents(abi, tr.getLogs());
        } catch (ABICodecException e) {
            log.error("decoder.decodeEvents failed", e);
        }
        for (Map.Entry<String,List<List<Object>>> entry : events.entrySet()) {

            if (!eventMetaInfoMap.containsKey(entry.getKey())){
                continue;
            }
            EventMetaInfo eventMetaInfo = eventMetaInfoMap.get(entry.getKey());
            int i = 0;
            for (List<Object> params : entry.getValue()) {
                EventBO eventBO = new EventBO();
                Map<String, Object> entity = Maps.newHashMap();
                for (FieldVO fieldVO : eventMetaInfo.getList()) {
                    if (CollectionUtil.isNotEmpty(config.getIgnoreParam())
                            && config.getIgnoreParam().containsKey(eventMetaInfo.getContractName())){
                        Map<String,List<String>> ignoreParamMap = config.getIgnoreParam().get(contractName);
                        if (ignoreParamMap.containsKey(eventMetaInfo.getEventName())){
                            if (ignoreParamMap.get(eventMetaInfo.getEventName()).contains(fieldVO.getSolidityName())){
                                i++;
                                continue;
                            }
                        }
                    }
                    if (params.get(i) instanceof java.util.List){
                        entity.put(fieldVO.getSqlName(), JSONUtil.toJsonStr(params.get(i++)));
                        continue;
                    }
                    entity.put(fieldVO.getSqlName(), params.get(i++));
                }
                entity.put("block_time_stamp", DateUtils.hexStrToDate(block.getTimestamp()));
                entity.put("tx_hash",tr.getTransactionHash());
                entity.put("contract_address", tr.getContractAddress());
                entity.put("block_height", Numeric.toBigInt(tr.getBlockNumber()).longValue());
                eventBO.setEntity(entity);
                eventBO.setTable(TableSQL.getTableName(contractName,eventMetaInfo.getEventName()));
                boList.add(eventBO);
            }
        }
        return boList;
    }

}
