package com.webank.blockchain.data.export;

import com.webank.blockchain.data.export.api.DataExportService;
import com.webank.blockchain.data.export.common.entity.ChainInfo;
import com.webank.blockchain.data.export.common.entity.ExportConfig;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.task.DataExportExecutor;
import org.fisco.bcos.sdk.config.exceptions.ConfigException;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/18
 */
public class ExportDataSDK {
    /**
     * create the executor with the default export configuration
     * @param dataSource dataSource config
     * @param chainInfo chain parameters
     * @return the executor
     * @throws ConfigException
     */
    public static DataExportExecutor create(ExportDataSource dataSource, ChainInfo chainInfo) throws ConfigException {
        return DataExportService.create(dataSource,chainInfo, new ExportConfig());
    }

    /**
     * create the executor with a custom export configuration
     * @param dataSource dataSource config
     * @param chainInfo chain parameters
     * @param config custom export configuration
     * @return the executor
     * @throws ConfigException
     */
    public static DataExportExecutor create(ExportDataSource dataSource, ChainInfo chainInfo, ExportConfig config) throws ConfigException {
        return DataExportService.create(dataSource,chainInfo,config);
    }

    /**
     * start the data export executor
     * @param exportExecutor the executor
     */
    public static void start(DataExportExecutor exportExecutor){
        DataExportService.start(exportExecutor);
    }

    /**
     * stop the data export executor
     * @param exportExecutor the executor
     */
    public static void stop(DataExportExecutor exportExecutor){
        DataExportService.stop(exportExecutor);
    }

}
