package com.webank.blockchain.data.export.sdk.test;

import com.webank.blockchain.data.export.ExportDataSDK;
import com.webank.blockchain.data.export.common.entity.ChainInfo;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.common.entity.MysqlDataSource;
import com.webank.blockchain.data.export.task.DataExportExecutor;
import org.fisco.bcos.sdk.config.exceptions.ConfigException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/21
 */
public class ExportDataTest {

    @Test
    public void shardingTest() throws ConfigException, InterruptedException {
        //配置其中[]内容配置即可测试
        MysqlDataSource mysqlDataSourc = MysqlDataSource.builder()
                .jdbcUrl("jdbc:mysql://[ip]:3306/[database]")
                .pass("password")
                .user("username")
                .build();
        MysqlDataSource mysqlDataSourc1 = MysqlDataSource.builder()
                .jdbcUrl("jdbc:mysql://[ip]:3306/[database]")
                .pass("password")
                .user("username")
                .build();
        List<MysqlDataSource> mysqlDataSourceList = new ArrayList<>();
        mysqlDataSourceList.add(mysqlDataSourc);
        mysqlDataSourceList.add(mysqlDataSourc1);
        ExportDataSource dataSource = ExportDataSource.builder()
                .mysqlDataSources(mysqlDataSourceList)
                .autoCreateTable(true)
                .sharding(true)
                .shardingNumberPerDatasource(2)
                .build();
        DataExportExecutor exportExecutor = ExportDataSDK.create(dataSource, ChainInfo.builder()
                .nodeStr("[ip]:[port]")
                .certPath("config")
                .groupId(1).build());
        ExportDataSDK.start(exportExecutor);
        Thread.sleep(60 *1000L);
        ExportDataSDK.stop(exportExecutor);
    }

    @Test
    public void singleTest() throws ConfigException, InterruptedException {
        MysqlDataSource mysqlDataSourc = MysqlDataSource.builder()
                .jdbcUrl("jdbc:mysql://[ip]:[port]/[database]")
                .pass("password")
                .user("username")
                .build();
        List<MysqlDataSource> mysqlDataSourceList = new ArrayList<>();
        mysqlDataSourceList.add(mysqlDataSourc);
        ExportDataSource dataSource = ExportDataSource.builder()
                .mysqlDataSources(mysqlDataSourceList)
                .autoCreateTable(true)
                .build();
        DataExportExecutor exportExecutor = ExportDataSDK.create(dataSource, ChainInfo.builder()
                .nodeStr("[ip]:[port]")
                .certPath("config")
                .groupId(1).build());
        ExportDataSDK.start(exportExecutor);
        Thread.sleep(60 *1000L);
        ExportDataSDK.stop(exportExecutor);
    }
}
