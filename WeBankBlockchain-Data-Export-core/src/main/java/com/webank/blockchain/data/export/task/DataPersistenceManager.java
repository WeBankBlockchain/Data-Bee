package com.webank.blockchain.data.export.task;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.db.DaoTemplate;
import cn.hutool.db.Db;
import cn.hutool.db.meta.MetaUtil;
import com.google.common.collect.Lists;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.ContractInfoBO;
import com.webank.blockchain.data.export.common.constants.ContractConstants;
import com.webank.blockchain.data.export.common.entity.DataExportContext;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.common.entity.ExportDataSource;
import com.webank.blockchain.data.export.common.entity.MysqlDataSource;
import com.webank.blockchain.data.export.common.entity.TableSQL;
import com.webank.blockchain.data.export.common.enums.DataType;
import com.webank.blockchain.data.export.db.dao.BlockDetailInfoDAO;
import com.webank.blockchain.data.export.db.dao.BlockRawDataDAO;
import com.webank.blockchain.data.export.db.dao.BlockTxDetailInfoDAO;
import com.webank.blockchain.data.export.db.dao.ContractInfoDAO;
import com.webank.blockchain.data.export.db.dao.DeployedAccountInfoDAO;
import com.webank.blockchain.data.export.db.dao.ESHandleDao;
import com.webank.blockchain.data.export.db.dao.MethodAndEventDao;
import com.webank.blockchain.data.export.db.dao.SaveInterface;
import com.webank.blockchain.data.export.db.dao.TxRawDataDAO;
import com.webank.blockchain.data.export.db.dao.TxReceiptRawDataDAO;
import com.webank.blockchain.data.export.db.repository.BlockDetailInfoRepository;
import com.webank.blockchain.data.export.db.repository.BlockRawDataRepository;
import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;
import com.webank.blockchain.data.export.db.repository.BlockTxDetailInfoRepository;
import com.webank.blockchain.data.export.db.repository.ContractInfoRepository;
import com.webank.blockchain.data.export.db.repository.DeployedAccountInfoRepository;
import com.webank.blockchain.data.export.db.repository.RollbackInterface;
import com.webank.blockchain.data.export.db.repository.TxRawDataRepository;
import com.webank.blockchain.data.export.db.repository.TxReceiptRawDataRepository;
import com.webank.blockchain.data.export.db.service.DataStoreService;
import com.webank.blockchain.data.export.db.service.ESStoreService;
import com.webank.blockchain.data.export.db.service.MysqlStoreService;
import com.webank.blockchain.data.export.tools.DataSourceUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.shardingsphere.driver.api.ShardingSphereDataSourceFactory;
import org.apache.shardingsphere.infra.config.algorithm.ShardingSphereAlgorithmConfiguration;
import org.apache.shardingsphere.sharding.api.config.ShardingRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.rule.ShardingTableRuleConfiguration;
import org.apache.shardingsphere.sharding.api.config.strategy.sharding.StandardShardingStrategyConfiguration;
import org.elasticsearch.client.transport.TransportClient;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import static com.webank.blockchain.data.export.common.entity.ExportConstant.BLOCK_DETAIL_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.BLOCK_RAW_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.BLOCK_TASK_POOL_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.BLOCK_TX_DETAIL_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.CONTRACT_INFO_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.DEPLOYED_ACCOUNT_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.TX_RAW_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.TX_RECEIPT_RAW_DAO;
import static com.webank.blockchain.data.export.common.entity.ExportConstant.tables;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/1/6
 */
@Data
@Slf4j
public class DataPersistenceManager {

    private BlockTaskPoolRepository blockTaskPoolRepository;
    private BlockDetailInfoRepository blockDetailInfoRepository;
    private BlockRawDataRepository blockRawDataRepository;
    private BlockTxDetailInfoRepository blockTxDetailInfoRepository;
    private TxRawDataRepository txRawDataRepository;
    private TxReceiptRawDataRepository txReceiptRawDataRepository;
    private DeployedAccountInfoRepository deployedAccountInfoRepository;
    private ContractInfoRepository contractInfoRepository;

    private List<DataStoreService> dataStoreServiceList = new ArrayList<>();
    private List<RollbackInterface> rollbackOneInterfaceList = new ArrayList<>();

    private DataExportContext context;

    public static DataPersistenceManager create(DataExportContext context) {
        return new DataPersistenceManager(context);
    }

    private DataPersistenceManager(DataExportContext context) {
        this.context = context;
    }

    public void saveContractInfo() {
        if (CollectionUtil.isEmpty(context.getConfig().getContractInfoList())) {
            return;
        }
        ContractMapsInfo mapsInfo = ContractConstants.contractMapsInfo.get();
        Map<String, ContractDetail> contractBinaryMap = mapsInfo.getContractBinaryMap();
        if (CollectionUtil.isEmpty(contractBinaryMap)) {
            return;
        }
        for (Map.Entry<String, ContractDetail> entry : contractBinaryMap.entrySet()) {
            ContractInfoBO contractInfoBO = entry.getValue().getContractInfoBO();
            for (DataStoreService storeService : dataStoreServiceList) {
                storeService.storeContractInfo(contractInfoBO);
            }
        }
    }

    public void buildDataStore() {
        context.setDataSource(
                DataSourceUtils.buildDataSource(
                        context.getExportDataSource(), DataType.getTables(context.getConfig().getDataTypeBlackList())));
        buildRepository();
        buildDao();
        buildESStore();
    }

    public void buildESStore() {
        if (context.getEsConfig() != null && context.getEsConfig().isEnable()) {
            TransportClient esClient = ESHandleDao.create();
            context.setEsClient(esClient);
            dataStoreServiceList.add(new ESStoreService());
        }
    }

    public void buildDao() {
        List<SaveInterface<BlockInfoBO>> saveInterfaceList = new ArrayList<>();
        MysqlStoreService mysqlStoreService = new MysqlStoreService();
        mysqlStoreService.setSaveInterfaceList(saveInterfaceList);
        dataStoreServiceList.add(mysqlStoreService);

        if (blockDetailInfoRepository != null) {
            BlockDetailInfoDAO blockDetailInfoDao = new BlockDetailInfoDAO(blockDetailInfoRepository);
            saveInterfaceList.add(blockDetailInfoDao);
        }
        if (blockTxDetailInfoRepository != null) {
            BlockTxDetailInfoDAO blockTxDetailInfoDao = new BlockTxDetailInfoDAO(blockTxDetailInfoRepository);
            saveInterfaceList.add(blockTxDetailInfoDao);
        }
        if (blockRawDataRepository != null) {
            BlockRawDataDAO blockRawDataDao = new BlockRawDataDAO(blockRawDataRepository);
            saveInterfaceList.add(blockRawDataDao);
        }
        if (txRawDataRepository != null) {
            TxRawDataDAO txRawDataDao = new TxRawDataDAO(txRawDataRepository);
            saveInterfaceList.add(txRawDataDao);
        }
        if (txReceiptRawDataRepository != null) {
            TxReceiptRawDataDAO txReceiptRawDataDao = new TxReceiptRawDataDAO(txReceiptRawDataRepository);
            saveInterfaceList.add(txReceiptRawDataDao);
        }
        if (deployedAccountInfoRepository != null) {
            DeployedAccountInfoDAO deployedAccountInfoDAO = new DeployedAccountInfoDAO(deployedAccountInfoRepository);
            saveInterfaceList.add(deployedAccountInfoDAO);
        }
        if (contractInfoRepository != null) {
            mysqlStoreService.setContractInfoDAO(new ContractInfoDAO(contractInfoRepository));
        }
        MethodAndEventDao methodAndEventDao = new MethodAndEventDao();
        saveInterfaceList.add(methodAndEventDao);
    }

    public void buildRepository() {
        Map<String, DaoTemplate> daoTemplateMap = buildDaoMap(context);
        blockTaskPoolRepository = new BlockTaskPoolRepository(
                daoTemplateMap.get(BLOCK_TASK_POOL_DAO));
        rollbackOneInterfaceList.add(blockTaskPoolRepository);
        List<DataType> blackTables = context.getConfig().getDataTypeBlackList();

        if (!blackTables.contains(DataType.BLOCK_DETAIL_INFO_TABLE)) {
            blockDetailInfoRepository = new BlockDetailInfoRepository(
                    daoTemplateMap.get(BLOCK_DETAIL_DAO));
            rollbackOneInterfaceList.add(blockDetailInfoRepository);
        }
        if (!blackTables.contains(DataType.BLOCK_RAW_DATA_TABLE)) {
            blockRawDataRepository = new BlockRawDataRepository(daoTemplateMap.get(
                    BLOCK_RAW_DAO));
            rollbackOneInterfaceList.add(blockRawDataRepository);
        }
        if (!blackTables.contains(DataType.BLOCK_TX_DETAIL_INFO_TABLE)) {
            blockTxDetailInfoRepository = new BlockTxDetailInfoRepository(
                    daoTemplateMap.get(BLOCK_TX_DETAIL_DAO));
            rollbackOneInterfaceList.add(blockTxDetailInfoRepository);
        }
        if (!blackTables.contains(DataType.TX_RAW_DATA_TABLE)) {
            txRawDataRepository = new TxRawDataRepository(
                    daoTemplateMap.get(TX_RAW_DAO));
            rollbackOneInterfaceList.add(txRawDataRepository);
        }
        if (!blackTables.contains(DataType.TX_RECEIPT_RAW_DATA_TABLE)) {
            txReceiptRawDataRepository = new TxReceiptRawDataRepository(
                    daoTemplateMap.get(TX_RECEIPT_RAW_DAO));
            rollbackOneInterfaceList.add(txReceiptRawDataRepository);
        }
        if (!blackTables.contains(DataType.DEPLOYED_ACCOUNT_INFO_TABLE)) {
            deployedAccountInfoRepository = new DeployedAccountInfoRepository(
                    daoTemplateMap.get(DEPLOYED_ACCOUNT_DAO));
        }
        if (!blackTables.contains(DataType.CONTRACT_INFO_TABLE)) {
            contractInfoRepository = new ContractInfoRepository(
                    daoTemplateMap.get(CONTRACT_INFO_DAO));
        }

    }

    public Map<String, DaoTemplate> buildDaoMap(DataExportContext context) {
        Db db = Db.use(context.getDataSource());
        Map<String, DaoTemplate> daoTemplateMap = new ConcurrentHashMap<>();
        tables.forEach(table -> {
            if (DataType.getTables(context.getConfig().getDataTypeBlackList()).contains(table)) {
                return;
            }
            DaoTemplate daoTemplate = new DaoTemplate(table, "pk_id", db);
            daoTemplateMap.put(table + "_dao", daoTemplate);
        });
        return daoTemplateMap;
    }



}
