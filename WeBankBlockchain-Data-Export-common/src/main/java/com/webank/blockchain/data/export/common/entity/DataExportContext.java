package com.webank.blockchain.data.export.common.entity;

import com.webank.blockchain.data.export.common.client.ChainClient;
import lombok.Data;
import org.elasticsearch.client.transport.TransportClient;
import org.fisco.bcos.sdk.transaction.codec.decode.TransactionDecoderInterface;

import javax.sql.DataSource;
import java.util.Map;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
@Data
@SuppressWarnings("deprecation")
public class DataExportContext {

    private DataSource dataSource;

    private ExportDataSource exportDataSource;

    private TransportClient esClient;

    private ESDataSource esConfig;

    private ChainInfo chainInfo;

    private StashInfo stashInfo;

    private DataSource stashDataSource;

    private ExportConfig config;

    private ChainClient client;

    private boolean autoCreateTable;

    private TransactionDecoderInterface decoder;

    private Map<String, ContractInfo> contractInfoMap;

}
