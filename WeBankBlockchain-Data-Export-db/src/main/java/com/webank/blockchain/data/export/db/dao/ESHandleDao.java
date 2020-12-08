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
package com.webank.blockchain.data.export.db.dao;

import cn.hutool.core.bean.BeanUtil;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.EventMetaInfo;
import com.webank.blockchain.data.export.common.bo.contract.MethodMetaInfo;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockTxDetailInfoBO;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import com.webank.blockchain.data.export.common.bo.data.DeployedAccountInfoBO;
import com.webank.blockchain.data.export.common.bo.data.EventBO;
import com.webank.blockchain.data.export.common.bo.data.MethodBO;
import com.webank.blockchain.data.export.common.bo.data.TxRawDataBO;
import com.webank.blockchain.data.export.common.bo.data.TxReceiptRawDataBO;
import com.webank.blockchain.data.export.db.config.ESBeanConfig;
import com.webank.blockchain.data.export.db.entity.DeployedAccountInfo;
import com.webank.blockchain.data.export.db.service.ESService;
import org.elasticsearch.client.transport.TransportClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Component
@ConditionalOnProperty(name = "es.enabled", havingValue = "true")
public class ESHandleDao {

    @Autowired
    private ESService esService;
    @Autowired
    private ESBeanConfig esBeanConfig;
    @Autowired
    private List<ContractDetail> contractDetails;

    public static final String BLOCK_DETAIL = "blockdetailinfo";

    public static final String BLOCK_RAW_DATA = "blockrawdata";

    public static final String TX_RAW_DATA = "txrawdata";

    public static final String DEPLOY_ACCOUNT = "deployaccountinfo";

    public static final String CONTRACT_INFO = "contractinfo";

    public static final String TX_RECEIPT_RAW_DATA = "txreceiptrawdata";

    public static final String BLOCK_TX_DETAIL = "blocktxdetailinfo";

    public static final String METHOD = "method";

    public static final String EVENT = "event";

    @PostConstruct
    public void initIndex() {
        TransportClient client = esBeanConfig.getClient();
        if (!esService.indexExists(client,BLOCK_DETAIL)){
            esService.createIndex(client,BLOCK_DETAIL);
        }
        if (!esService.indexExists(client,BLOCK_RAW_DATA)){
            esService.createIndex(client,BLOCK_RAW_DATA);
        }
        if (!esService.indexExists(client,TX_RAW_DATA)){
            esService.createIndex(client,TX_RAW_DATA);
        }
        if (!esService.indexExists(client,DEPLOY_ACCOUNT)){
            esService.createIndex(client,DEPLOY_ACCOUNT);
        }
        if (!esService.indexExists(client,CONTRACT_INFO)){
            esService.createIndex(client,CONTRACT_INFO);
        }
        if (!esService.indexExists(client,TX_RECEIPT_RAW_DATA)){
            esService.createIndex(client,TX_RECEIPT_RAW_DATA);
        }
        if (!esService.indexExists(client,BLOCK_TX_DETAIL)){
            esService.createIndex(client,BLOCK_TX_DETAIL);
        }
        for(ContractDetail contractDetail : contractDetails) {
            for (MethodMetaInfo methodMetaInfo : contractDetail.getMethodMetaInfos()) {
                String index = (contractDetail.getContractInfoBO().getContractName() + methodMetaInfo.getMethodName() +
                        METHOD).toLowerCase();
                if (!esService.indexExists(client,index)) {
                    esService.createIndex(client, index);
                }
            }
            for (EventMetaInfo eventMetaInfo : contractDetail.getEventMetaInfos()) {
                String index = (contractDetail.getContractInfoBO().getContractName() + eventMetaInfo.getEventName() +
                        EVENT).toLowerCase();
                if (!esService.indexExists(client,index)) {
                    esService.createIndex(client, index);
                }
            }
        }
    }

    public void saveBlockInfo(BlockInfoBO blockInfoBO) {
        esService.createDocument(esBeanConfig.getClient(),
                BLOCK_DETAIL, "_doc", String.valueOf(blockInfoBO.getBlockDetailInfo().getBlockHeight()),
                blockInfoBO.getBlockDetailInfo());

        esService.createDocument(esBeanConfig.getClient(),
                BLOCK_RAW_DATA,"_doc", String.valueOf(blockInfoBO.getBlockRawDataBO().getBlockHeight()),
                blockInfoBO.getBlockRawDataBO());

        for (TxRawDataBO txRawDataBO : blockInfoBO.getTxRawDataBOList()) {
            esService.createDocument(esBeanConfig.getClient(),
                    TX_RAW_DATA,"_doc",
                    txRawDataBO.getTxHash(), txRawDataBO);
        }

        for (DeployedAccountInfoBO deployedAccountInfoBO : blockInfoBO.getDeployedAccountInfoBOS()) {
            DeployedAccountInfo deployedAccountInfo = new DeployedAccountInfo();
            BeanUtil.copyProperties(deployedAccountInfoBO, deployedAccountInfo, true);
            esService.createDocument(esBeanConfig.getClient(),
                    DEPLOY_ACCOUNT,"_doc",
                    deployedAccountInfoBO.getContractAddress(),
                    deployedAccountInfo);
        }

        for (TxReceiptRawDataBO txReceiptRawDataBO : blockInfoBO.getTxReceiptRawDataBOList()) {
            esService.createDocument(esBeanConfig.getClient(),
                    TX_RECEIPT_RAW_DATA,"_doc",
                    txReceiptRawDataBO.getTxHash(),
                    txReceiptRawDataBO);
        }

        for (BlockTxDetailInfoBO blockTxDetailInfoBO : blockInfoBO.getBlockTxDetailInfoList()) {
            esService.createDocument(esBeanConfig.getClient(),
                    BLOCK_TX_DETAIL,"_doc",
                    blockTxDetailInfoBO.getTxHash(),
                    blockTxDetailInfoBO);
        }

        for (EventBO eventBO : blockInfoBO.getEventInfoList()) {
            esService.createDocument(esBeanConfig.getClient(),
                    eventBO.getIdentifier().toLowerCase() + EVENT,
                    "_doc", eventBO.getTxHash(), eventBO);
        }

        for (MethodBO methodBO : blockInfoBO.getMethodInfoList()) {
            esService.createDocument(esBeanConfig.getClient(),
                     methodBO.getIdentifier().toLowerCase() + METHOD,
                    "_doc", methodBO.getTxHash(), methodBO);
        }
    }

    public void saveContractInfo(ContractInfoBO contractInfoBO) {
        esService.createDocument(esBeanConfig.getClient(),
                CONTRACT_INFO, "_doc",contractInfoBO);
    }

}
