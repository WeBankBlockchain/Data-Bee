/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.db.service;

import com.webank.blockchain.data.export.db.vo.CommonBiParaQueryPageReq;
import com.webank.blockchain.data.export.db.vo.CommonPageRes;
import com.webank.blockchain.data.export.db.vo.CommonParaQueryPageReq;
import com.webank.blockchain.data.export.db.vo.CommonSpecificationQueryPageReq;
import com.webank.blockchain.data.export.db.specification.CommonReqParaSpecification;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;

import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.date.DateException;

/**
 * CommonQueryService is a common service for querying one page of object list by a param type and value.
 *
 * @Description: CommonQueryService
 * @author graysonzhang
 * @data 2018-12-24 10:57:02
 *
 */
@Service
@SuppressWarnings("unchecked")
public class CommonQueryService {

    /**
     * get one page of object list by param type and value.
     * 
     * @param req: CommonParaQueryPageReq contains order, orderBy, pageNo, pageSize, paramType, paramValue
     * @param repository
     * @return: CommonResponse
     */
    public <T> CommonResponse getPageListByCommonReq(CommonParaQueryPageReq<String> req,
                                                     JpaSpecificationExecutor<T> repository) {
        try {
            PageRequest pr = (PageRequest) req.convert();
            Specification<T> spec = CommonReqParaSpecification.queryByCriteriaEqual(req);
            Page<T> page = repository.findAll(spec, pr);
            CommonPageRes<T> ret = new CommonPageRes<>(req);
            ret.setResult(page.getContent()).setTotalCount(page.getTotalElements()).setPageNo(req.getPageNo())
                    .setPageSize(req.getPageSize());
            return ResponseUtils.data(ret);
        } catch (DateException e) {
            return ResponseUtils.paramError("invalid date format " + e.getMessage());
        }
    }

    public <T> CommonResponse getPageListByCommonReq(CommonBiParaQueryPageReq<String> req,
                                                     JpaSpecificationExecutor<T> repository) {
        PageRequest pr = (PageRequest) req.convert();
        try {
            if (StringUtils.isEmpty(req.getReqParaValue1()) || StringUtils.isEmpty(req.getReqParaName1())) {
                return ResponseUtils.paramError("para1 should not be empty");
            }
            if (StringUtils.isEmpty(req.getReqParaValue2()) || StringUtils.isEmpty(req.getReqParaName2())) {
                CommonParaQueryPageReq<String> uniReq = new CommonParaQueryPageReq<>();
                BeanUtil.copyProperties(req, uniReq);
                uniReq.setReqParaName(req.getReqParaName1()).setReqParaValue(req.getReqParaValue1());
                return getPageListByCommonReq(uniReq, repository);
            }
            Specification<T> spec = CommonReqParaSpecification.queryByCriteriaEqual(req);
            Page<T> page = repository.findAll(spec, pr);
            CommonPageRes<T> ret = new CommonPageRes<>(req);
            ret.setResult(page.getContent()).setTotalCount(page.getTotalElements()).setPageNo(req.getPageNo())
                    .setPageSize(req.getPageSize());
            return ResponseUtils.data(ret);
        } catch (DateException e) {
            return ResponseUtils.paramError("invalid date format " + e.getMessage());
        }
    }

    public <T> CommonResponse getPageListByCommonReq(CommonSpecificationQueryPageReq req,
                                                     JpaSpecificationExecutor<T> repository) {
        PageRequest pr = (PageRequest) req.convert();
        try {
            Specification<T> spec = CommonReqParaSpecification.queryByCriteriaEqual(req);
            Page<T> page = repository.findAll(spec, pr);
            CommonPageRes<T> ret = new CommonPageRes<>(req);
            ret.setResult(page.getContent()).setTotalCount(page.getTotalElements()).setPageNo(req.getPageNo())
                    .setPageSize(req.getPageSize());
            return ResponseUtils.data(ret);
        } catch (DateException e) {
            return ResponseUtils.paramError("invalid date format " + e.getMessage());
        }
    }

}
