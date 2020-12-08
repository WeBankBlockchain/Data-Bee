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
package com.webank.blockchain.data.export.core.api.controller;

import javax.validation.Valid;

import com.webank.blockchain.data.export.db.vo.UnitBiParaQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitParaQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitSpecificationQueryPageReq;
import com.webank.blockchain.data.export.db.vo.UnitTimeRangeQueryPageReq;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;
import com.webank.blockchain.data.export.core.api.manager.EventManager;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * EventController
 *
 * @Description: EventController
 * @author maojiayu
 * @data Dec 24, 2018 11:06:25 AM
 *
 */
@RestController
@RequestMapping("/api/event")
@Api(value = "EventController", tags = "Event Infomation Query")
public class EventController {
    @Autowired
    private EventManager eventManager;

    @PostMapping("paras/get")
    @ApiOperation(value = "get by event and paras. The unit name means your event name, eg. xxContractxxEvent.", httpMethod = "POST")
    public CommonResponse getByEventParas(@RequestBody @Valid UnitParaQueryPageReq<String> req, BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return eventManager.getPageListByReq(req);
    }

    @PostMapping("biparas/get")
    @ApiOperation(value = "get by event and paras, the first para name and value is required, and the second para name and value is optional.This means if your second para name or value is empty, then it will only return the result equals to the first para name and value. The unit name means your event name, eg. xxContractxxEvent.", httpMethod = "POST")
    public CommonResponse getByEventBiParas(@RequestBody @Valid UnitBiParaQueryPageReq<String> req,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return eventManager.getPageListByReq(req);
    }

    @PostMapping("specification/get")
    @ApiOperation(value = "get by event and paras specification.", httpMethod = "POST")
    public CommonResponse getByEventBiParas(@RequestBody @Valid UnitSpecificationQueryPageReq req,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        if (CollectionUtils.isEmpty(req.getAndConditions()) && CollectionUtils.isEmpty(req.getOrConditions())) {
            return ResponseUtils.paramError("The query conditions can't be null");
        }
        return eventManager.getPageListByReq(req);
    }

    @PostMapping("name/get")
    @ApiOperation(value = "get by event name", httpMethod = "POST")
    public CommonResponse getByEventName(@RequestBody @Valid UnitQueryPageReq<String> req, BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return eventManager.find(req);
    }

    @ResponseBody
    @RequestMapping("/time/get")
    @ApiOperation(value = "Base on time range", httpMethod = "POST")
    public CommonResponse getListByTimeRange(@RequestBody @Valid UnitTimeRangeQueryPageReq req, BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return eventManager.getPageListByReq(req);
    }

}
