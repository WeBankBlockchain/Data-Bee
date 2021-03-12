package com.webank.blockchain.data.export.tools;

import org.apache.shardingsphere.elasticjob.api.JobConfiguration;
import org.apache.shardingsphere.elasticjob.reg.base.CoordinatorRegistryCenter;
import org.apache.shardingsphere.elasticjob.reg.zookeeper.ZookeeperConfiguration;
import org.apache.shardingsphere.elasticjob.reg.zookeeper.ZookeeperRegistryCenter;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/22
 */
public class ElasticJobUtil {

    public static CoordinatorRegistryCenter createRegistryCenter(String zookeeperServiceLists, String zookeeperNamespace) {
        CoordinatorRegistryCenter regCenter = new ZookeeperRegistryCenter(new ZookeeperConfiguration(
                zookeeperServiceLists,zookeeperNamespace));
        regCenter.init();
        return regCenter;
    }

    public static JobConfiguration createJobConfiguration(String jobName, String cron,
                                                           int shardingCount, String shardingItemParameters) {
        return JobConfiguration.newBuilder(jobName, shardingCount)
                .cron(cron).shardingItemParameters(shardingItemParameters).build();
    }
}
