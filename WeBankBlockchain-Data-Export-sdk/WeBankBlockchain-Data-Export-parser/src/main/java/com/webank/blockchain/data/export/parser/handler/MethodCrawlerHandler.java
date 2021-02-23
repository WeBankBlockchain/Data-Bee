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
import cn.hutool.json.JSONUtil;
import com.google.common.collect.Maps;
import com.webank.blockchain.data.export.common.bo.contract.FieldVO;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;
import com.webank.blockchain.data.export.common.bo.data.BlockMethodInfo;
import com.webank.blockchain.data.export.common.bo.data.BlockTxDetailInfoBO;
import com.webank.blockchain.data.export.common.bo.data.MethodBO;
import com.webank.blockchain.data.export.common.bo.data.TxRawDataBO;
import com.webank.blockchain.data.export.common.bo.data.TxReceiptRawDataBO;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.entity.TableSQL;
import com.webank.blockchain.data.export.common.tools.DateUtils;
import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.common.tools.MethodUtils;
import com.webank.blockchain.data.export.parser.service.TransactionService;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.protocol.model.JsonTransactionResponse;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.Block;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.TransactionObject;
import org.fisco.bcos.sdk.client.protocol.response.BcosBlock.TransactionResult;
import org.fisco.bcos.sdk.model.TransactionReceipt;
import org.fisco.bcos.sdk.transaction.codec.decode.TransactionDecoderInterface;
import org.fisco.bcos.sdk.transaction.model.dto.TransactionResponse;
import org.fisco.bcos.sdk.utils.Numeric;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


/**
 * MethodCrawlerHandler
 *
 * @Description: MethodCrawlerHandler
 * @author maojiayu
 * @data Jul 3, 2019 10:17:15 AM
 *
 */
@Slf4j
public class MethodCrawlerHandler {

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static BlockMethodInfo crawl(Block block,  Map<String, String> txHashContractAddressMapping) throws IOException {
        BlockMethodInfo blockMethodInfo = new BlockMethodInfo();
        List<BlockTxDetailInfoBO> blockTxDetailInfoList = new ArrayList<>();
        List<TxRawDataBO> txRawDataBOList = new ArrayList<>();
        List<TxReceiptRawDataBO> txReceiptRawDataBOList = new ArrayList<>();
        List<MethodBO> methodInfoList = new ArrayList();
        List<TransactionResult> transactionResults = block.getTransactions();
        Map<String, String> txHashContractNameMapping = new HashMap<>();
        for (TransactionResult result : transactionResults) {
            TransactionObject to = (TransactionObject) result;
            JsonTransactionResponse transaction = to.get();
            Optional<TransactionReceipt> opt = ExportConstant.getCurrentContext().getClient()
                            .getTransactionReceipt(transaction.getHash()).getTransactionReceipt();
            Optional<String> contractName = TransactionService.getContractNameByTransaction(transaction, txHashContractAddressMapping);
            if (!contractName.isPresent()){
                continue;
            }
            MethodMetaInfo methodMetaInfo = TransactionService.getMethodMetaInfo(transaction, contractName.get());
            if (methodMetaInfo == null) {
                continue;
            }
            if (opt.isPresent()) {
                TransactionReceipt receipt = opt.get();
                Map<String, ContractInfo> contractAbiMap = ExportConstant.getCurrentContext().getContractInfoMap();
                String abi = contractAbiMap.get(contractName.get()).getAbi();
                if (abi == null){
                    continue;
                }
                MethodBO methodBO = parseMethod(block,methodMetaInfo, receipt,abi);
                if (methodBO != null){
                    methodInfoList.add(methodBO);
                }
                // get block tx detail info
                BlockTxDetailInfoBO blockTxDetailInfo =
                        getBlockTxDetailInfo(block, transaction, receipt, methodMetaInfo);
                TxRawDataBO txRawDataBO = getTxRawDataBO(block, transaction, receipt);
                TxReceiptRawDataBO txReceiptRawDataBO = getTxReceiptRawDataBO(block, receipt);
                blockTxDetailInfoList.add(blockTxDetailInfo);
                txRawDataBOList.add(txRawDataBO);
                txReceiptRawDataBOList.add(txReceiptRawDataBO);
                txHashContractNameMapping.putIfAbsent(blockTxDetailInfo.getTxHash(),
                        blockTxDetailInfo.getContractName());
            }
        }
        blockMethodInfo.setBlockTxDetailInfoList(blockTxDetailInfoList)
                .setMethodInfoList(methodInfoList)
                .setTxHashContractNameMapping(txHashContractNameMapping)
                .setTxRawDataBOList(txRawDataBOList)
                .setTxReceiptRawDataBOList(txReceiptRawDataBOList);
        return blockMethodInfo;

    }

    public static MethodBO parseMethod(Block block, MethodMetaInfo methodMetaInfo, TransactionReceipt receipt, String abi){
        TransactionDecoderInterface decoder = ExportConstant.getCurrentContext().getDecoder();
        ExportConfig config = ExportConstant.getCurrentContext().getConfig();
        MethodBO methodBO = null;
        try {
            List<Object> params = MethodUtils.decodeMethodInput(abi, methodMetaInfo.getMethodName(), receipt,
                    ExportConstant.getCurrentContext().getClient());
            if(CollectionUtil.isEmpty(params)) {
                return null;
            }
            methodBO = new MethodBO();
            Map<String, Object> entity = Maps.newHashMap();
            entity.put("block_time_stamp", DateUtils.hexStrToDate(block.getTimestamp()));
            entity.put("tx_hash", receipt.getTransactionHash());
            entity.put("contract_address", receipt.getContractAddress());
            entity.put("block_height", Numeric.toBigInt(receipt.getBlockNumber()).longValue());
            entity.put("method_status", receipt.getStatus());
            methodBO.setEntity(entity);
            methodBO.setTable(TableSQL.getTableName(methodMetaInfo.getContractName(), methodMetaInfo.getMethodName()));
            TransactionResponse response;
            if (!CollectionUtil.isEmpty(methodMetaInfo.getOutputList())) {
                response = decoder.decodeReceiptWithValues(abi, methodMetaInfo.getMethodName(), receipt);
                List<Object> returns = response.getValuesList();
                int i = 0;
                for (FieldVO fieldVO : methodMetaInfo.getOutputList()) {
                    if (CollectionUtil.isNotEmpty(config.getIgnoreParam())
                            && config.getIgnoreParam().containsKey(methodMetaInfo.getContractName())){
                        Map<String,List<String>> ignoreParamMap = config.getIgnoreParam().get(methodMetaInfo.getContractName());
                        if (ignoreParamMap.containsKey(methodMetaInfo.getMethodName())){
                            if (ignoreParamMap.get(methodMetaInfo.getMethodName()).contains(fieldVO.getJavaName())){
                                i++;
                                continue;
                            }
                        }
                    }
                    entity.put(fieldVO.getSqlName(), returns.get(i++));
                }
            }
            List<FieldVO> fieldVOS = methodMetaInfo.getFieldsList();
            if (CollectionUtil.isEmpty(fieldVOS)) {
                return methodBO;
            }
            for (int i = 0; i < fieldVOS.size(); i++) {
                if (CollectionUtil.isNotEmpty(config.getIgnoreParam())
                        && config.getIgnoreParam().containsKey(methodMetaInfo.getContractName())){
                    Map<String,List<String>> ignoreParamMap = config.getIgnoreParam().get(methodMetaInfo.getContractName());
                    if (ignoreParamMap.containsKey(methodMetaInfo.getMethodName())){
                        if (ignoreParamMap.get(methodMetaInfo.getMethodName()).contains(fieldVOS.get(i).getSolidityName())){
                            continue;
                        }
                    }
                }
                if (params.get(i) instanceof java.util.List){
                    entity.put(fieldVOS.get(i).getSqlName(), JSONUtil.toJsonStr(params.get(i)));
                    continue;
                }
                entity.put(fieldVOS.get(i).getSqlName(), params.get(i));
            }
        } catch (Exception e) {
            log.error("decoder.decodeEvents failed", e);
        }
        return methodBO;
    }

    public static BlockTxDetailInfoBO getBlockTxDetailInfo(Block block, JsonTransactionResponse transaction,
            TransactionReceipt receipt, MethodMetaInfo methodMetaInfo) {
        BlockTxDetailInfoBO blockTxDetailInfo = new BlockTxDetailInfoBO();
        blockTxDetailInfo.setBlockHash(receipt.getBlockHash()).setBlockHeight(receipt.getBlockNumber())
                .setContractName(methodMetaInfo.getContractName())
                .setMethodName(methodMetaInfo.getMethodName())
                .setTxFrom(transaction.getFrom()).setTxTo(transaction.getTo()).setTxHash(receipt.getTransactionHash())
                .setBlockTimeStamp(DateUtils.hexStrToDate(block.getTimestamp()));
        return blockTxDetailInfo;
    }

    public static TxRawDataBO getTxRawDataBO(Block block, JsonTransactionResponse transaction, TransactionReceipt receipt) {
        TxRawDataBO txRawDataBO = new TxRawDataBO();
        txRawDataBO.setBlockHash(receipt.getBlockHash())
                .setBlockHeight(Numeric.decodeQuantity((receipt.getBlockNumber())).longValue())
                .setBlockTimeStamp(DateUtils.hexStrToDate(block.getTimestamp()))
                .setTxHash(receipt.getTransactionHash())
                .setTxIndex(transaction.getTransactionIndex())
                .setFrom(transaction.getFrom())
                .setGas(transaction.getGas())
                .setGasPrice(transaction.getGasPrice())
                .setInput(transaction.getInput())
                .setNonce(transaction.getNonce())
                .setTo(transaction.getTo())
                .setValue(transaction.getValue());
        return txRawDataBO;
    }

    public static TxReceiptRawDataBO getTxReceiptRawDataBO(Block block, TransactionReceipt receipt) {
        TxReceiptRawDataBO txReceiptRawDataBO = new TxReceiptRawDataBO();
        txReceiptRawDataBO.setBlockHash(receipt.getBlockHash())
                .setBlockHeight(Numeric.decodeQuantity((receipt.getBlockNumber())).longValue())
                .setBlockTimeStamp(DateUtils.hexStrToDate(block.getTimestamp()))
                .setTxHash(receipt.getTransactionHash())
                .setContractAddress(receipt.getContractAddress())
                .setFrom(receipt.getFrom())
                .setGasUsed(receipt.getGasUsed())
                .setInput(receipt.getInput())
                .setLogs(receipt.getLogsBloom())
                .setMessage(receipt.getMessage())
                .setOutput(receipt.getOutput())
                .setLogsBloom(JacksonUtils.toJson(receipt.getLogsBloom()))
                .setRoot(receipt.getRoot())
                .setTo(receipt.getTo())
                .setTxIndex(receipt.getTransactionIndex())
                .setTxProof(JacksonUtils.toJson(receipt.getTxProof()))
                .setReceiptProof(JacksonUtils.toJson(receipt.getReceiptProof()));
        return txReceiptRawDataBO;
    }

}
