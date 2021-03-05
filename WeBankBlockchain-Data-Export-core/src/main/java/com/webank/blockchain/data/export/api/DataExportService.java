package com.webank.blockchain.data.export.api;

import cn.hutool.core.collection.CollectionUtil;
import com.webank.blockchain.data.export.common.entity.BlockDataSource;
import com.webank.blockchain.data.export.common.entity.ChainInfo;
import com.webank.blockchain.data.export.common.entity.ContractInfo;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.common.entity.StashInfo;
import com.webank.blockchain.data.export.task.DataExportExecutor;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
@Slf4j
public class DataExportService {

    public static DataExportExecutor create(ExportDataSource dataSource, BlockDataSource blockDataSource, ExportConfig config) throws Exception {
        return new DataExportExecutor(buildContext(dataSource, blockDataSource, config));
    }

    public static void start(DataExportExecutor exportExecutor) {
        exportExecutor.start();
    }

    public static void stop(DataExportExecutor exportExecutor) {
        exportExecutor.stop();
    }

    private static DataExportContext buildContext(ExportDataSource dataSource, BlockDataSource blockDataSource, ExportConfig config) throws Exception {
        DataExportContext context = new DataExportContext();
        if (CollectionUtil.isNotEmpty(config.getContractInfoList())) {
            Map<String, ContractInfo> contractInfoMap = config.getContractInfoList().stream()
                    .collect(Collectors.toMap(ContractInfo::getContractName, e->e));
            context.setContractInfoMap(contractInfoMap);
        }
        if (blockDataSource instanceof ChainInfo){
            context.setChainInfo((ChainInfo) blockDataSource);
        }
        if (blockDataSource instanceof StashInfo){
            context.setStashInfo((StashInfo) blockDataSource);
        }
        context.setConfig(config);
        context.setExportDataSource(dataSource);
        context.setEsConfig(dataSource.getEsDataSource());
        context.setAutoCreateTable(dataSource.isAutoCreateTable());
        return context;
    }
}
