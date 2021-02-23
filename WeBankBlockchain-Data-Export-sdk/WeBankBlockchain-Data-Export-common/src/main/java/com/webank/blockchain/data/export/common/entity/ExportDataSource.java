package com.webank.blockchain.data.export.common.entity;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/16
 */
@Data
@Builder
public class ExportDataSource {

    private boolean autoCreateTable;

    private boolean sharding;

    private int shardingNumberPerDatasource;

    private List<MysqlDataSource> mysqlDataSources;

    private ESDataSource esDataSource;
}
