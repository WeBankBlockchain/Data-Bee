package com.webank.blockchain.data.export.common.entity;

import lombok.Data;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/17
 */
@Data
public class ESDataSource {

    private boolean enable;
    private String clusterName;
    private String ip;
    private int port;
}
