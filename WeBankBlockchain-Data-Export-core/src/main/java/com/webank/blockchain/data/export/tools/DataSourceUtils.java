package com.webank.blockchain.data.export.tools;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.db.Db;
import cn.hutool.db.meta.MetaUtil;
import cn.hutool.setting.dialect.Props;
import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.common.entity.MysqlDataSource;
import com.webank.blockchain.data.export.common.entity.TableSQL;
import com.webank.blockchain.data.export.common.enums.DataType;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.extern.slf4j.Slf4j;
import org.apache.shardingsphere.driver.api.ShardingSphereDataSourceFactory;
import org.apache.shardingsphere.infra.config.algorithm.ShardingSphereAlgorithmConfiguration;
import org.apache.shardingsphere.sharding.api.config.ShardingRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.rule.ShardingTableRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.strategy.sharding.StandardShardingStrategyConfiguration;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/17
 */
@Slf4j
public class DataSourceUtils {

    public static DataSource createDataSource(String jdbcUrl, String driver, String user, String pass) {
        final Props config = new Props();
        config.put("jdbcUrl", jdbcUrl);
        if (null != driver) {
            config.put("driverClassName", driver);
        }
        if (null != user) {
            config.put("username", user);
        }
        if (null != pass) {
            config.put("password", pass);
        }

        return new HikariDataSource(new HikariConfig(config));
    }


    public static DataSource buildDataSource(ExportDataSource exportDataSource, List<String> blackTables) {
        if (!exportDataSource.isSharding()) {
            return buildSingleDataSource(exportDataSource.getMysqlDataSources().get(0),
                    exportDataSource.isAutoCreateTable(), blackTables);
        } else {
            return buildShardingDataSource(exportDataSource.getMysqlDataSources(),
                    exportDataSource.getShardingNumberPerDatasource(),
                    exportDataSource.isAutoCreateTable(), blackTables);
        }
    }

    private static DataSource buildSingleDataSource(MysqlDataSource mysqlDataSource) {
        return buildSingleDataSource(mysqlDataSource, false, null);
    }


    private static DataSource buildSingleDataSource(MysqlDataSource mysqlDataSource, boolean autoCreateTable,
                                                    List<String> blackTables) {
        DataSource dataSource = DataSourceUtils.createDataSource(mysqlDataSource.getJdbcUrl(),
                null,
                mysqlDataSource.getUser(),
                mysqlDataSource.getPass());
        if (autoCreateTable) {
            createTable(dataSource, blackTables);
        }
        return dataSource;
    }

    private static DataSource buildShardingDataSource(List<MysqlDataSource> mysqlDataSources,
                                                      int shardingNumberPerDatasource,
                                                      boolean autoCreateTable, List<String> blackTables) {
        Map<String, DataSource> dataSourceMap = new HashMap<>();
        String dsName = "ds";
        String tablePrefix = ExportConstant.getCurrentContext().getConfig().getTablePrefix();
        String tablePostfix = ExportConstant.getCurrentContext().getConfig().getTablePostfix();
        int i = 0;
        for (MysqlDataSource dataSource : mysqlDataSources) {
            DataSource ds = buildSingleDataSource(dataSource);
            dataSourceMap.put(dsName + i++, ds);
            if (autoCreateTable) {
                creatShardingTables(ds, shardingNumberPerDatasource, blackTables);
            }
        }
        // 配置分片规则
        ShardingRuleConfiguration shardingRuleConfig = new ShardingRuleConfiguration();

        List<String> tables = Lists.newArrayList();
        tables.addAll(ExportConstant.tables);
        //event and method tables
        addMethodAndEventTables(tables);

        for (String table : tables) {
            if (table.equals(ExportConstant.BLOCK_TASK_POOL_TABLE) || table.equals(ExportConstant.CONTRACT_INFO_TABLE)) {
                continue;
            }
            if (ExportConstant.tables.contains(table)) {
                table = tablePrefix + table + tablePostfix;
            }
            // table rule
            ShardingTableRuleConfiguration orderTableRuleConfig = new
                    ShardingTableRuleConfiguration(table, "ds${0..1}." + table + "${0..1}");
            // database rule
            orderTableRuleConfig.setDatabaseShardingStrategy(
                    new StandardShardingStrategyConfiguration("block_height", table + "_dbShardingAlgorithm"));
            // table order rule
            orderTableRuleConfig.setTableShardingStrategy(
                    new StandardShardingStrategyConfiguration("block_height", table + "_tableShardingAlgorithm"));
            shardingRuleConfig.getTables().add(orderTableRuleConfig);

            // database Algorithm
            Properties dbShardingAlgorithmrProps = new Properties();
            dbShardingAlgorithmrProps.setProperty("algorithm-expression",
                    dsName + "${block_height % " + mysqlDataSources.size() + "}");
            // table Algorithm
            Properties tableShardingAlgorithmrProps = new Properties();
            tableShardingAlgorithmrProps.setProperty("algorithm-expression",
                    table + "${block_height % " + shardingNumberPerDatasource + "}");
            shardingRuleConfig.getShardingAlgorithms().put(table + "_dbShardingAlgorithm",
                    new ShardingSphereAlgorithmConfiguration("INLINE", dbShardingAlgorithmrProps));
            shardingRuleConfig.getShardingAlgorithms().put(table + "_tableShardingAlgorithm",
                    new ShardingSphereAlgorithmConfiguration("INLINE", tableShardingAlgorithmrProps));
        }
        try {
            return ShardingSphereDataSourceFactory.createDataSource(dataSourceMap,
                    Collections.singleton(shardingRuleConfig), new Properties());
        } catch (SQLException e) {
            log.error("ShardingSphereDataSourceFactory createDataSource failed ", e);
        }
        return null;
    }

    private static void addMethodAndEventTables(List<String> tables) {
        //event and method tables
        ContractMapsInfo mapsInfo = ContractConstants.getCurrentContractMaps();
        if (mapsInfo != null) {
            for (Map.Entry<String, ContractDetail> contractDetailMap : mapsInfo.getContractBinaryMap().entrySet()) {
                ContractDetail contractDetail = contractDetailMap.getValue();
                if (CollectionUtil.isNotEmpty(contractDetail.getEventMetaInfos())) {
                    contractDetail.getEventMetaInfos().forEach(eventMetaInfo ->
                            tables.add(TableSQL.getTableName(eventMetaInfo.getContractName(), eventMetaInfo.getEventName())));
                }
                if (CollectionUtil.isNotEmpty(contractDetail.getMethodMetaInfos())) {
                    contractDetail.getMethodMetaInfos().forEach(methodMetaInfo ->
                            tables.add(TableSQL.getTableName(methodMetaInfo.getContractName(), methodMetaInfo.getMethodName())));
                }
            }
        }
    }

    private static void creatShardingTables(DataSource ds, int shardingNumberPerDatasource, List<String> blackTables) {
        log.info("export data auto create table begin....");
        String tablePrefix = ExportConstant.getCurrentContext().getConfig().getTablePrefix();
        String tablePostfix = ExportConstant.getCurrentContext().getConfig().getTablePostfix();
        Db db = Db.use(ds);
        List<String> tables = MetaUtil.getTables(ds);
        try {
            for (Map.Entry<String, String> entry : TableSQL.tableSqlMap.entrySet()) {
                if (blackTables.contains(entry.getKey())) {
                    continue;
                }
                if (entry.getKey().equals(ExportConstant.BLOCK_TASK_POOL_TABLE)
                        || entry.getKey().equals(ExportConstant.CONTRACT_INFO_TABLE)) {
                    if (!tables.contains(tablePrefix + entry.getKey() + tablePostfix)) {
                        db.execute(entry.getValue().replaceFirst(entry.getKey(), tablePrefix + entry.getKey() + tablePostfix));
                    }
                    continue;
                }
                for (int i = 0; i < shardingNumberPerDatasource; i++) {
                    if (!tables.contains(tablePrefix + entry.getKey() + tablePostfix + i)) {
                        db.execute(entry.getValue().replaceFirst(entry.getKey(), tablePrefix + entry.getKey()  + tablePostfix + i));
                    }
                }
            }
            createMethodAndEventShardingTable(db, blackTables, tables, shardingNumberPerDatasource);
        } catch (SQLException e) {
            log.error("export data table create failed, reason is : ", e);
            Thread.currentThread().interrupt();
        }
        log.info("export data auto create table success !");
    }

    private static void createTable(DataSource ds, List<String> blackTables) {
        log.info("export data auto create table begin....");
        String tablePrefix = ExportConstant.getCurrentContext().getConfig().getTablePrefix();
        String tablePostfix = ExportConstant.getCurrentContext().getConfig().getTablePostfix();
        try {
            Db db = Db.use(ds);
            List<String> tables = MetaUtil.getTables(ds);
            for (Map.Entry<String, String> entry : TableSQL.tableSqlMap.entrySet()) {
                if (blackTables.contains(entry.getKey())) {
                    continue;
                }
                if (!tables.contains(tablePrefix + entry.getKey() + tablePostfix)) {
                    db.execute(entry.getValue().replaceFirst(entry.getKey(), tablePrefix + entry.getKey() + tablePostfix));
                }
            }
            createMethodAndEventTable(db, blackTables, tables);
        } catch (SQLException e) {
            log.error("export data table create failed, reason is : ", e);
            Thread.currentThread().interrupt();
        }
        log.info("export data auto create table success !");
    }

    private static void createMethodAndEventTable(Db db, List<String> blackTables, List<String> tables) {
        ContractMapsInfo mapsInfo = ContractConstants.getCurrentContractMaps();
        if (mapsInfo == null) {
            return;
        }
        for (Map.Entry<String, ContractDetail> contractDetailMap : mapsInfo.getContractBinaryMap().entrySet()) {
            ContractDetail contractDetail = contractDetailMap.getValue();
            if (!blackTables.contains(DataType.METHOD_TABLE.getTableName()) && CollectionUtil.isNotEmpty(contractDetail.getMethodMetaInfos())) {
                contractDetail.getMethodMetaInfos().forEach(methodMetaInfo -> {
                    String tableSql = TableSQL.createMethodTableSql(methodMetaInfo);
                    try {
                        if (!tables.contains(TableSQL.getTableName(methodMetaInfo.getContractName(),
                                methodMetaInfo.getMethodName()))) {
                            db.execute(tableSql);
                        }
                    } catch (SQLException e) {
                        log.error("export data table create failed, reason is : ", e);
                    }
                });
            }
            if (!blackTables.contains(DataType.EVENT_TABLE.getTableName()) && CollectionUtil.isNotEmpty(contractDetail.getEventMetaInfos())) {
                contractDetail.getEventMetaInfos().forEach(eventMetaInfo -> {
                    String tableSql = TableSQL.createEventTableSql(eventMetaInfo);
                    try {
                        if (!tables.contains(TableSQL.getTableName(eventMetaInfo.getContractName(),
                                eventMetaInfo.getEventName()))) {
                            db.execute(tableSql);
                        }
                    } catch (SQLException e) {
                        log.error("export data table create failed, reason is : ", e);
                    }
                });
            }
        }
    }

    private static void createMethodAndEventShardingTable(Db db, List<String> blackTables,
                                                          List<String> tables, int shardingNumberPerDatasource) {
        ContractMapsInfo mapsInfo = ContractConstants.getCurrentContractMaps();
        if (mapsInfo == null) {
            return;
        }
        for (Map.Entry<String, ContractDetail> contractDetailMap : mapsInfo.getContractBinaryMap().entrySet()) {
            ContractDetail contractDetail = contractDetailMap.getValue();
            if (!blackTables.contains(DataType.METHOD_TABLE.getTableName()) && CollectionUtil.isNotEmpty(contractDetail.getMethodMetaInfos())) {
                contractDetail.getMethodMetaInfos().forEach(methodMetaInfo -> {
                    String tableSql = TableSQL.createMethodTableSql(methodMetaInfo);
                    try {
                        for (int i = 0; i < shardingNumberPerDatasource; i++) {
                            String tableName = TableSQL.getTableName(methodMetaInfo.getContractName(),
                                    methodMetaInfo.getMethodName());
                            if (!tables.contains(tableName + i)) {
                                db.execute(tableSql.replaceFirst(tableName, tableName + i));
                            }
                        }
                    } catch (SQLException e) {
                        log.error("export data table create failed, reason is : ", e);
                    }
                });
            }
            if (!blackTables.contains(DataType.EVENT_TABLE.getTableName()) && CollectionUtil.isNotEmpty(contractDetail.getEventMetaInfos())) {
                contractDetail.getEventMetaInfos().forEach(eventMetaInfo -> {
                    String tableSql = TableSQL.createEventTableSql(eventMetaInfo);
                    try {
                        for (int i = 0; i < shardingNumberPerDatasource; i++) {
                            String tableName = TableSQL.getTableName(eventMetaInfo.getContractName(),
                                    eventMetaInfo.getEventName());
                            if (!tables.contains(tableName + i)) {
                                db.execute(tableSql.replaceFirst(tableName, tableName + i));
                            }
                        }
                    } catch (SQLException e) {
                        log.error("export data table create failed, reason is : ", e);
                    }
                });
            }
        }
    }
}
