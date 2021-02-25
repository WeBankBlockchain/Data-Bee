package com.webank.blockchain.data.export.api;

import cn.hutool.core.collection.CollectionUtil;
import com.googlecode.jsonrpc4j.JsonRpcHttpClient;
import com.webank.blockchain.data.export.common.entity.ChainClient;
import com.webank.blockchain.data.export.common.entity.ChainInfo;
import com.webank.blockchain.data.export.common.entity.ChannelClient;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.common.entity.RpcHttpClient;
import com.webank.blockchain.data.export.task.DataExportExecutor;
import com.webank.blockchain.data.export.tools.ClientUtil;
import lombok.extern.slf4j.Slf4j;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.CryptoSuite;

import java.net.URL;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
@Slf4j
public class DataExportService {

    public static DataExportExecutor create(ExportDataSource dataSource, ChainInfo chainInfo, ExportConfig config) throws Exception {
        return new DataExportExecutor(buildContext(dataSource, chainInfo, config));
    }

    public static void start(DataExportExecutor exportExecutor) {
        exportExecutor.start();
    }

    public static void stop(DataExportExecutor exportExecutor) {
        exportExecutor.stop();
    }

    private static DataExportContext buildContext(ExportDataSource dataSource, ChainInfo chainInfo, ExportConfig config) throws Exception {
        DataExportContext context = new DataExportContext();
        if (CollectionUtil.isNotEmpty(config.getContractInfoList())) {
            Map<String, ContractInfo> contractInfoMap = config.getContractInfoList().stream()
                    .collect(Collectors.toMap(ContractInfo::getContractName, e->e));
            context.setContractInfoMap(contractInfoMap);
        }
        ChainClient chainClient;
        if (chainInfo.getRpcUrl() != null) {
            JsonRpcHttpClient jsonRpcHttpClient = new JsonRpcHttpClient(new URL(chainInfo.getRpcUrl()));
            chainClient = new RpcHttpClient(jsonRpcHttpClient, chainInfo.getGroupId(),
                    new CryptoSuite(chainInfo.getCryptoTypeConfig()));
        } else {
            Client client = ClientUtil.getClient(chainInfo);
            chainClient = new ChannelClient(client);
        }
        context.setClient(chainClient);
        context.setChainInfo(chainInfo);
        context.setConfig(config);
        context.setExportDataSource(dataSource);
        context.setEsConfig(dataSource.getEsDataSource());
        context.setAutoCreateTable(dataSource.isAutoCreateTable());
        return context;
    }
}
